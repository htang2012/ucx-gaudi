/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_COPY_IFACE_H
#define UCT_GAUDI_COPY_IFACE_H


#include <ucs/datastruct/static_bitmap.h>
#include <ucs/memory/memory_type.h>
#include <uct/base/uct_iface.h>
#include <uct/gaudi/base/gaudi_iface.h>

#include <pthread.h>

typedef uint64_t uct_gaudi_copy_iface_addr_t;


typedef struct uct_gaudi_copy_iface {
    uct_gaudi_iface_t           super;
    /* used to store uuid and check iface reachability */
    uct_gaudi_copy_iface_addr_t id;
    /* config parameters to control gaudi copy transport */
    struct {
        double                  bandwidth;
        size_t                  async_max_inflight;
        double                  latency_overhead;
        size_t                  bcopy_thresh;
        ucs_config_bw_spec_t    bandwidth_spec[UCS_MEMORY_TYPE_LAST][UCS_MEMORY_TYPE_LAST];
    } config;
    /* handler to support arm/wakeup feature */
    struct {
        void                    *event_arg;
        uct_async_event_cb_t    event_cb;
    } async;
} uct_gaudi_copy_iface_t;


typedef struct uct_gaudi_copy_iface_config {
    uct_iface_config_t      super;
    unsigned                max_poll;
    unsigned                max_gaudi_events;
    double                  bandwidth;
    size_t                  async_max_inflight;
    double                  latency_overhead;
    size_t                  bcopy_thresh;
    ucs_config_bw_spec_t    bandwidth_h2d;
    ucs_config_bw_spec_t    bandwidth_d2h;
    ucs_config_bw_spec_t    bandwidth_d2d;
} uct_gaudi_copy_iface_config_t;

#endif