/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_iface.h"
#include "gaudi_md.h"

#include <ucs/sys/string.h>
#include <ucs/type/class.h>


ucs_status_t
uct_gaudi_base_query_devices_common(
        uct_md_h md, uct_device_type_t dev_type,
        uct_tl_device_resource_t **tl_devices_p, unsigned *num_tl_devices_p)
{
    return uct_single_device_resource(md, md->component->name,
                                      dev_type,
                                      UCS_SYS_DEVICE_ID_UNKNOWN,
                                      tl_devices_p, num_tl_devices_p);
}

ucs_status_t
uct_gaudi_base_query_devices(uct_md_h md,
                             uct_tl_device_resource_t **tl_devices_p,
                             unsigned *num_tl_devices_p)
{
    return uct_single_device_resource(md, md->component->name,
                                      UCT_DEVICE_TYPE_ACC,
                                      UCS_SYS_DEVICE_ID_UNKNOWN,
                                      tl_devices_p, num_tl_devices_p);
}

UCS_CLASS_INIT_FUNC(uct_gaudi_iface_t, uct_iface_ops_t *tl_ops,
                   uct_iface_internal_ops_t *ops, uct_md_h md,
                   uct_worker_h worker, const uct_iface_params_t *params,
                   const uct_iface_config_t *tl_config)
{
    UCS_CLASS_CALL_SUPER_INIT(uct_base_iface_t, tl_ops, ops, md, worker, 
                               params, tl_config UCS_STATS_ARG(NULL) UCS_STATS_ARG("gaudi"));
    return UCS_OK;
}

UCS_CLASS_CLEANUP_FUNC(uct_gaudi_iface_t)
{
    /* Nothing to cleanup for now */
}

UCS_CLASS_DEFINE(uct_gaudi_iface_t, uct_base_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_gaudi_iface_t, uct_iface_t, uct_iface_ops_t*,
                          uct_iface_internal_ops_t*, uct_md_h, uct_worker_h, 
                          const uct_iface_params_t*, const uct_iface_config_t*);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_gaudi_iface_t, uct_iface_t);