/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_H
#define UCT_GAUDI_H

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>

/* Include Synapse API - hlthunk no longer supported */
#include <habanalabs/synapse_api.h>
#include <habanalabs/synapse_api_types.h>
#include <habanalabs/synapse_common_types.h>

/* Gaudi device types for UCX */
typedef synDeviceId uct_gaudi_device_handle_t;
typedef synStreamHandle uct_gaudi_stream_handle_t;

/* Synapse API wrapper functions */
#define uct_gaudi_open_device(device_idx, bus_id) synDeviceAcquire(&device_idx, NULL)
#define uct_gaudi_close_device(device_handle) synDeviceRelease(device_handle)
#define uct_gaudi_get_device_info(device_handle, info) synDeviceGetInfo(device_handle, info)

BEGIN_C_DECLS

/* Forward declarations */
typedef struct uct_gaudi_iface uct_gaudi_iface_t;

/* Include subheaders */
#include "gaudi_md.h"
#include "gaudi_iface.h"

END_C_DECLS

#endif