/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifndef UCT_GAUDI_IPC_IFACE_H
#define UCT_GAUDI_IPC_IFACE_H

#include <uct/base/uct_iface.h>
#include <uct/gaudi/base/gaudi_iface.h>
#include <ucs/arch/cpu.h>

#include "gaudi_ipc_md.h"
#include "gaudi_ipc_ep.h"
#include "gaudi_ipc_cache.h"


typedef struct {
    double                  bandwidth;
    double                  latency;
    double                  overhead;
} uct_gaudi_ipc_iface_config_params_t;


typedef struct {
    uct_gaudi_iface_t                   super;
    uct_gaudi_ipc_iface_config_params_t config;
} uct_gaudi_ipc_iface_t;


typedef struct {
    uct_iface_config_t                 super;
    uct_gaudi_ipc_iface_config_params_t params;
} uct_gaudi_ipc_iface_config_t;

#endif
