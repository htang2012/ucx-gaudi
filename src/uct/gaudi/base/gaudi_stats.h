/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_STATS_H
#define UCT_GAUDI_STATS_H

#include <ucs/stats/stats.h>
#include <ucs/time/time.h>

/* Performance monitoring macro for enhanced statistics */
#define UCT_GAUDI_STAT_ADD(_stats, _counter, _value) \
    do { \
        if ((_stats) != NULL) { \
            UCS_STATS_UPDATE_COUNTER((_stats), (_counter), (_value)); \
        } \
    } while (0)

/* Timing statistics macro */
#define UCT_GAUDI_STAT_TIME(_stats, _counter, _start_time) \
    do { \
        if ((_stats) != NULL) { \
            ucs_time_t _duration = ucs_get_time() - (_start_time); \
            UCS_STATS_UPDATE_COUNTER((_stats), (_counter), _duration); \
        } \
    } while (0)

/* Enhanced performance monitoring structure */
typedef struct uct_gaudi_perf_monitor {
    ucs_time_t      last_update_time;
    uint64_t        total_operations;
    uint64_t        total_bytes;
    double          avg_bandwidth;
    double          avg_latency;
} uct_gaudi_perf_monitor_t;

/* Initialize performance monitor */
static inline void uct_gaudi_perf_monitor_init(uct_gaudi_perf_monitor_t *monitor)
{
    monitor->last_update_time = ucs_get_time();
    monitor->total_operations = 0;
    monitor->total_bytes = 0;
    monitor->avg_bandwidth = 0.0;
    monitor->avg_latency = 0.0;
}

/* Update performance monitor with operation data */
static inline void uct_gaudi_perf_monitor_update(uct_gaudi_perf_monitor_t *monitor,
                                                size_t bytes, ucs_time_t latency)
{
    ucs_time_t current_time = ucs_get_time();
    ucs_time_t time_diff = current_time - monitor->last_update_time;
    
    monitor->total_operations++;
    monitor->total_bytes += bytes;
    
    if (time_diff > 0) {
        monitor->avg_bandwidth = (double)bytes / ucs_time_to_sec(time_diff);
    }
    
    /* Simple exponential moving average for latency */
    if (monitor->total_operations == 1) {
        monitor->avg_latency = ucs_time_to_sec(latency);
    } else {
        monitor->avg_latency = 0.9 * monitor->avg_latency + 0.1 * ucs_time_to_sec(latency);
    }
    
    monitor->last_update_time = current_time;
}

#endif /* UCT_GAUDI_STATS_H */