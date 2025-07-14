/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_ipc_iface.h"
#include "gaudi_ipc_md.h"
#include "gaudi_ipc_ep.h"

#include <uct/gaudi/base/gaudi_iface.h>
#include <uct/gaudi/base/gaudi_md.h>
#include <ucs/type/class.h>
#include <ucs/sys/string.h>
#include <ucs/debug/assert.h>
#include <ucs/async/eventfd.h>
#include <pthread.h>


static ucs_config_field_t uct_gaudi_ipc_iface_config_table[] = {

    {"", "", NULL,
     ucs_offsetof(uct_gaudi_ipc_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    {"BW", "auto",
     "Effective p2p memory bandwidth",
     ucs_offsetof(uct_gaudi_ipc_iface_config_t, params.bandwidth), UCS_CONFIG_TYPE_BW},

    {"LAT", "1.8us",
     "Estimated latency",
     ucs_offsetof(uct_gaudi_ipc_iface_config_t, params.latency), UCS_CONFIG_TYPE_TIME},

    {"OVERHEAD", "4.0us",
     "Estimated CPU overhead for transferring GPU memory",
     ucs_offsetof(uct_gaudi_ipc_iface_config_t, params.overhead), UCS_CONFIG_TYPE_TIME},
    {NULL}
};


/* Forward declaration for the delete function */
static void UCS_CLASS_DELETE_FUNC_NAME(uct_gaudi_ipc_iface_t)(uct_iface_t*);


ucs_status_t uct_gaudi_ipc_iface_get_device_address(uct_iface_t *tl_iface,
                                                   uct_device_addr_t *addr)
{
    return UCS_OK;
}

static ucs_status_t uct_gaudi_ipc_iface_get_address(uct_iface_h tl_iface,
                                                   uct_iface_addr_t *iface_addr)
{
    *(pid_t*)iface_addr = getpid();
    return UCS_OK;
}

static int
uct_gaudi_ipc_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                   const uct_iface_is_reachable_params_t *params)
{
    if (!uct_iface_is_reachable_params_addrs_valid(params)) {
        return 0;
    }

    if (getpid() == *(pid_t*)params->iface_addr) {
        uct_iface_fill_info_str_buf(params, "same process");
        return 0;
    }

    return uct_iface_scope_is_reachable(tl_iface, params);
}

static double uct_gaudi_ipc_iface_get_bw()
{
    return 6911.0  * UCS_MBYTE;
}

static ucs_status_t uct_gaudi_ipc_iface_query(uct_iface_h tl_iface,
                                             uct_iface_attr_t *iface_attr)
{
    uct_gaudi_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_gaudi_ipc_iface_t);

    uct_base_iface_query(&iface->super.super, iface_attr);

    iface_attr->iface_addr_len          = sizeof(pid_t);
    iface_attr->device_addr_len         = 0;
    iface_attr->ep_addr_len             = 0;
    iface_attr->max_conn_priv           = 0;
    iface_attr->cap.flags               = UCT_IFACE_FLAG_CONNECT_TO_IFACE |
                                          UCT_IFACE_FLAG_GET_ZCOPY        |
                                          UCT_IFACE_FLAG_PUT_ZCOPY;

    iface_attr->cap.put.max_short       = 0;
    iface_attr->cap.put.max_bcopy       = 0;
    iface_attr->cap.put.min_zcopy       = 0;
    iface_attr->cap.put.max_zcopy       = ULONG_MAX;
    iface_attr->cap.put.opt_zcopy_align = 1;
    iface_attr->cap.put.align_mtu       = iface_attr->cap.put.opt_zcopy_align;
    iface_attr->cap.put.max_iov         = 1;

    iface_attr->cap.get.max_bcopy       = 0;
    iface_attr->cap.get.min_zcopy       = 0;
    iface_attr->cap.get.max_zcopy       = ULONG_MAX;
    iface_attr->cap.get.opt_zcopy_align = 1;
    iface_attr->cap.get.align_mtu       = iface_attr->cap.get.opt_zcopy_align;
    iface_attr->cap.get.max_iov         = 1;

    iface_attr->latency                 = ucs_linear_func_make(1e-6, 0);
    iface_attr->bandwidth.dedicated     = 0;
    iface_attr->bandwidth.shared        = iface->config.bandwidth;
    iface_attr->overhead                = 7.0e-6;
    iface_attr->priority                = 0;

    return UCS_OK;
}

static uct_iface_ops_t uct_gaudi_ipc_iface_ops = {
    .ep_get_zcopy             = uct_gaudi_ipc_ep_get_zcopy,
    .ep_put_zcopy             = uct_gaudi_ipc_ep_put_zcopy,
    .ep_pending_add           = (uct_ep_pending_add_func_t)ucs_empty_function_return_busy,
    .ep_pending_purge         = (uct_ep_pending_purge_func_t)ucs_empty_function,
    .ep_flush                 = uct_base_ep_flush,
    .ep_fence                 = uct_base_ep_fence,
    .ep_check                 = (uct_ep_check_func_t)ucs_empty_function_return_unsupported,
    .ep_create                = UCS_CLASS_NEW_FUNC_NAME(uct_gaudi_ipc_ep_t),
    .ep_destroy               = UCS_CLASS_DELETE_FUNC_NAME(uct_gaudi_ipc_ep_t),
    .iface_flush              = uct_base_iface_flush,
    .iface_fence              = uct_base_iface_fence,
    .iface_progress_enable    = uct_base_iface_progress_enable,
    .iface_progress_disable   = uct_base_iface_progress_disable,
    .iface_progress           = (uct_iface_progress_func_t)ucs_empty_function_return_zero,
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_gaudi_ipc_iface_t),
    .iface_query              = uct_gaudi_ipc_iface_query,
    .iface_get_device_address = uct_gaudi_ipc_iface_get_device_address,
    .iface_get_address        = uct_gaudi_ipc_iface_get_address,
    .iface_is_reachable       = uct_base_iface_is_reachable,
};

static ucs_status_t
uct_gaudi_ipc_estimate_perf(uct_iface_h tl_iface, uct_perf_attr_t *perf_attr)
{
    uct_gaudi_ipc_iface_t *iface = ucs_derived_of(tl_iface, uct_gaudi_ipc_iface_t);

    perf_attr->bandwidth.dedicated = 0;

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_BANDWIDTH) {
        perf_attr->bandwidth.shared = uct_gaudi_ipc_iface_get_bw();
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_PATH_BANDWIDTH) {
        perf_attr->path_bandwidth.dedicated = 0;
        perf_attr->path_bandwidth.shared    = uct_gaudi_ipc_iface_get_bw();
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_SEND_PRE_OVERHEAD) {
        perf_attr->send_pre_overhead = iface->config.overhead;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_SEND_POST_OVERHEAD) {
        perf_attr->send_post_overhead = 0;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_RECV_OVERHEAD) {
        perf_attr->recv_overhead = 0;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_LATENCY) {
        perf_attr->latency = ucs_linear_func_make(iface->config.latency, 0.0);
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_MAX_INFLIGHT_EPS) {
        perf_attr->max_inflight_eps = SIZE_MAX;
    }

    if (perf_attr->field_mask & UCT_PERF_ATTR_FIELD_FLAGS) {
        perf_attr->flags = 0;
    }

    return UCS_OK;
}

static uct_iface_internal_ops_t uct_gaudi_ipc_iface_internal_ops = {
    .iface_estimate_perf   = uct_gaudi_ipc_estimate_perf,
    .iface_vfs_refresh     = (uct_iface_vfs_refresh_func_t)ucs_empty_function,
    .ep_query              = (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
    .ep_invalidate         = (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
    .ep_connect_to_ep_v2   = (uct_ep_connect_to_ep_v2_func_t)ucs_empty_function_return_unsupported,
    .iface_is_reachable_v2 = uct_gaudi_ipc_iface_is_reachable_v2,
    .ep_is_connected       = uct_gaudi_ipc_ep_is_connected
};

static UCS_CLASS_INIT_FUNC(uct_gaudi_ipc_iface_t, uct_md_h md, uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config)
{
    uct_gaudi_ipc_iface_config_t *config = NULL;

    config = ucs_derived_of(tl_config, uct_gaudi_ipc_iface_config_t);
    UCS_CLASS_CALL_SUPER_INIT(uct_gaudi_iface_t, &uct_gaudi_ipc_iface_ops,
                              &uct_gaudi_ipc_iface_internal_ops, md, worker, params,
                              tl_config);

    self->config = config->params;
    if (UCS_CONFIG_DBL_IS_AUTO(config->params.bandwidth)) {
        self->config.bandwidth = uct_gaudi_ipc_iface_get_bw() ;
    }

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_gaudi_ipc_iface_t)
{
}

ucs_status_t
uct_gaudi_ipc_query_devices(
        uct_md_h uct_md, uct_tl_device_resource_t **tl_devices_p,
        unsigned *num_tl_devices_p)
{
    return uct_gaudi_base_query_devices_common(uct_md, UCT_DEVICE_TYPE_SHM,
                                              tl_devices_p, num_tl_devices_p);
}

UCS_CLASS_DEFINE(uct_gaudi_ipc_iface_t, uct_base_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_gaudi_ipc_iface_t, uct_iface_t, uct_md_h, uct_worker_h,
                          const uct_iface_params_t*, const uct_iface_config_t*);
static UCS_CLASS_DEFINE_DELETE_FUNC(uct_gaudi_ipc_iface_t, uct_iface_t);

UCT_TL_DEFINE(&uct_gaudi_ipc_component.super, gaudi_ipc,
              uct_gaudi_ipc_query_devices, uct_gaudi_ipc_iface_t, "GAUDI_IPC_",
              uct_gaudi_ipc_iface_config_table, uct_gaudi_ipc_iface_config_t);
