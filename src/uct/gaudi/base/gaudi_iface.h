/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifndef UCT_GAUDI_IFACE_H
#define UCT_GAUDI_IFACE_H

#include <uct/base/uct_iface.h>
#include <ucs/sys/preprocessor.h>
#include <ucs/profile/profile.h>
#include <ucs/async/eventfd.h>
#include <ucs/datastruct/khash.h>

#include <hlthunk.h>


#define UCT_GAUDI_FUNC(_func, _log_level) \
    ({ \
        ucs_status_t _status = UCS_OK; \
        do { \
            int _err = (_func); \
            if (0 != _err) { \
                ucs_log((_log_level), "%s failed: %s", \
                        UCS_PP_MAKE_STRING(_func), \
                        "gaudi thunk error"); \
                _status = UCS_ERR_IO_ERROR; \
            } \
        } while (0); \
        _status; \
    })


#define UCT_GAUDI_FUNC_LOG_ERR(_func) \
    UCT_GAUDI_FUNC(_func, UCS_LOG_LEVEL_ERROR)


#define UCT_GAUDI_FUNC_LOG_WARN(_func) \
    UCT_GAUDI_FUNC(_func, UCS_LOG_LEVEL_WARN)


#define UCT_GAUDI_FUNC_LOG_DEBUG(_func) \
_UCT_GAUDI_FUNC(_func, UCS_LOG_LEVEL_DEBUG)

typedef struct uct_gaudi_iface {
    uct_base_iface_t          super;
    /* list of queues which require progress */
    ucs_queue_head_t          active_queue;
} uct_gaudi_iface_t;

ucs_status_t
uct_gaudi_base_query_devices_common(
        uct_md_h md, uct_device_type_t dev_type,
        uct_tl_device_resource_t **tl_devices_p, unsigned *num_tl_devices_p);

ucs_status_t
uct_gaudi_base_query_devices(uct_md_h md,
                             uct_tl_device_resource_t **tl_devices_p,
                             unsigned *num_tl_devices_p);

void
uct_gaudi_base_get_sys_dev(int gaudi_device, ucs_sys_device_t *sys_dev_p);

ucs_status_t
uct_gaudi_base_get_gaudi_device(ucs_sys_device_t sys_dev, int *device);

UCS_CLASS_DECLARE(uct_gaudi_iface_t, uct_iface_ops_t*, uct_iface_internal_ops_t*,
                  uct_md_h, uct_worker_h, const uct_iface_params_t*,
                  const uct_iface_config_t*);

#endif
