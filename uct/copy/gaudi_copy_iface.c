/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_copy_iface.h"
#include "gaudi_copy_ep.h"

#include <uct/gaudi/base/gaudi_iface.h>
#include <uct/gaudi/base/gaudi_md.h>
#include <ucs/type/class.h>
#include <ucs/sys/string.h>
#include <ucs/async/eventfd.h>
#include <ucs/arch/cpu.h>
#include <inttypes.h>


#define UCT_GAUDI_COPY_IFACE_OVERHEAD 0
#define UCT_GAUDI_COPY_IFACE_LATENCY  ucs_linear_func_make(8e-6, 0)

extern uct_component_t uct_gaudi_copy_component;

static ucs_config_field_t uct_gaudi_copy_iface_config_table[] = {

    {"", "", NULL,
     ucs_offsetof(uct_gaudi_copy_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    {"MAX_POLL", "16",
     "Max number of event completions to pick during gaudi events polling",
     ucs_offsetof(uct_gaudi_copy_iface_config_t, max_poll), UCS_CONFIG_TYPE_UINT},

    {"MAX_EVENTS", "inf",
     "Max number of gaudi events. -1 is infinite",
     ucs_offsetof(uct_gaudi_copy_iface_config_t, max_gaudi_events), UCS_CONFIG_TYPE_UINT},

    {"BW", "10000MBs",
     "Effective memory bandwidth",
     ucs_offsetof(uct_gaudi_copy_iface_config_t, bandwidth), UCS_CONFIG_TYPE_BW},

    {NULL}
};

static ucs_status_t uct_gaudi_copy_iface_get_address(uct_iface_t *tl_iface,
                                                     uct_iface_addr_t *iface_addr)
{
    uct_gaudi_copy_iface_t *iface = ucs_derived_of(tl_iface, uct_gaudi_copy_iface_t);
    *(uct_gaudi_copy_iface_addr_t*)iface_addr = iface->id;
    return UCS_OK;
}

static int uct_gaudi_copy_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                                const uct_iface_is_reachable_params_t *params)
{
    uct_gaudi_copy_iface_t *iface = ucs_derived_of(tl_iface,
                                                   uct_gaudi_copy_iface_t);
    uct_gaudi_copy_iface_addr_t *addr;

    if (!uct_iface_is_reachable_params_addrs_valid(params)) {
        return 0;
    }

    addr = (uct_gaudi_copy_iface_addr_t*)params->iface_addr;
    if (addr == NULL) {
        uct_iface_fill_info_str_buf(params, "device address is empty");
        return 0;
    }

    if (iface->id != *addr) {
        uct_iface_fill_info_str_buf(
            params, "iface id mismatch, iface->id=%"PRIu64", addr->id=%"PRIu64,
            iface->id, *addr);
        return 0;
    }

    return 1;
}

static ucs_status_t uct_gaudi_copy_iface_query(uct_iface_h tl_iface,
                                               uct_iface_attr_t *iface_attr)
{
    uct_gaudi_copy_iface_t *iface = ucs_derived_of(tl_iface, uct_gaudi_copy_iface_t);

    uct_base_iface_query(&iface->super.super, iface_attr);

    iface_attr->iface_addr_len          = sizeof(uct_gaudi_copy_iface_addr_t);
    iface_attr->device_addr_len         = 0;
    iface_attr->ep_addr_len             = 0;
    iface_attr->cap.flags               = UCT_IFACE_FLAG_CONNECT_TO_IFACE |
                                          UCT_IFACE_FLAG_GET_ZCOPY |
                                          UCT_IFACE_FLAG_PUT_ZCOPY |
                                          UCT_IFACE_FLAG_PENDING;

    iface_attr->cap.put.max_zcopy       = SIZE_MAX;
    iface_attr->cap.get.max_zcopy       = SIZE_MAX;

    iface_attr->latency                 = UCT_GAUDI_COPY_IFACE_LATENCY;
    iface_attr->bandwidth.dedicated     = 0;
    iface_attr->bandwidth.shared        = iface->config.bandwidth;
    iface_attr->overhead                = UCT_GAUDI_COPY_IFACE_OVERHEAD;
    iface_attr->priority                = 0;

    return UCS_OK;
}

/* Forward declarations */
static UCS_CLASS_INIT_FUNC(uct_gaudi_copy_iface_t, uct_md_h md, uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config);

static UCS_CLASS_CLEANUP_FUNC(uct_gaudi_copy_iface_t);

/* Class definitions - must be before ops structures that reference them */
UCS_CLASS_DEFINE(uct_gaudi_copy_iface_t, uct_gaudi_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_gaudi_copy_iface_t, uct_iface_t, uct_md_h, uct_worker_h, 
                          const uct_iface_params_t*, const uct_iface_config_t*);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_gaudi_copy_iface_t, uct_iface_t);

static uct_iface_ops_t uct_gaudi_copy_iface_tl_ops = {
    .ep_put_zcopy             = uct_gaudi_copy_ep_put_zcopy,
    .ep_get_zcopy             = uct_gaudi_copy_ep_get_zcopy,
    .ep_pending_add           = (uct_ep_pending_add_func_t)ucs_empty_function_return_busy,
    .ep_pending_purge         = (uct_ep_pending_purge_func_t)ucs_empty_function,
    .ep_flush                 = (uct_ep_flush_func_t)ucs_empty_function_return_success,
    .ep_fence                 = (uct_ep_fence_func_t)ucs_empty_function_return_success,
    .ep_check                 = (uct_ep_check_func_t)ucs_empty_function_return_success,
    .ep_create                = UCS_CLASS_NEW_FUNC_NAME(uct_gaudi_copy_ep_t),
    .ep_destroy               = UCS_CLASS_DELETE_FUNC_NAME(uct_gaudi_copy_ep_t),
    .iface_flush              = (uct_iface_flush_func_t)ucs_empty_function_return_success,
    .iface_fence              = (uct_iface_fence_func_t)ucs_empty_function_return_success,
    .iface_progress_enable    = (uct_iface_progress_enable_func_t)ucs_empty_function,
    .iface_progress_disable   = (uct_iface_progress_disable_func_t)ucs_empty_function,
    .iface_progress           = (uct_iface_progress_func_t)ucs_empty_function_return_zero,
    .iface_event_fd_get       = (uct_iface_event_fd_get_func_t)ucs_empty_function_return_unsupported,
    .iface_event_arm          = (uct_iface_event_arm_func_t)ucs_empty_function_return_success,
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_gaudi_copy_iface_t),
    .iface_query              = uct_gaudi_copy_iface_query,
    .iface_get_address        = uct_gaudi_copy_iface_get_address,
    .iface_get_device_address = (uct_iface_get_device_address_func_t)ucs_empty_function_return_success,
    .iface_is_reachable       = uct_base_iface_is_reachable,
};

static uct_iface_internal_ops_t uct_gaudi_copy_iface_internal_ops = {
    .iface_estimate_perf   = (uct_iface_estimate_perf_func_t)ucs_empty_function_return_unsupported,
    .iface_vfs_refresh     = (uct_iface_vfs_refresh_func_t)ucs_empty_function,
    .ep_query              = (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
    .ep_invalidate         = (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
    .ep_connect_to_ep_v2   = (uct_ep_connect_to_ep_v2_func_t)ucs_empty_function_return_unsupported,
    .iface_is_reachable_v2 = uct_gaudi_copy_iface_is_reachable_v2,
    .ep_is_connected       = (uct_ep_is_connected_func_t)ucs_empty_function_return_unsupported
};

static UCS_CLASS_CLEANUP_FUNC(uct_gaudi_copy_iface_t)
{
    /* Nothing to cleanup for now */
}

/* Class function implementations */
static UCS_CLASS_INIT_FUNC(uct_gaudi_copy_iface_t, uct_md_h md, uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config)
{
    uct_gaudi_copy_iface_config_t *config = ucs_derived_of(tl_config,
                                                           uct_gaudi_copy_iface_config_t);

    UCS_CLASS_CALL_SUPER_INIT(uct_gaudi_iface_t, &uct_gaudi_copy_iface_tl_ops,
                              &uct_gaudi_copy_iface_internal_ops, md, worker,
                              params, tl_config);

    self->id = (uintptr_t)self;
    self->config.bandwidth = config->bandwidth;

    return UCS_OK;
}

UCT_TL_DEFINE(&uct_gaudi_copy_component, gaudi_cpy, uct_gaudi_base_query_devices,
              uct_gaudi_copy_iface_t, "GAUDI_COPY_",
              uct_gaudi_copy_iface_config_table, uct_gaudi_copy_iface_config_t);
