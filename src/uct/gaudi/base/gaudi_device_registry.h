/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_DEVICE_REGISTRY_H
#define UCT_GAUDI_DEVICE_REGISTRY_H

#include <ucs/type/status.h>
#include <ucs/sys/topo/base/topo.h>
#include <habanalabs/synapse_api.h>

ucs_status_t uct_gaudi_device_open(int , const char *bus_id_str, synDeviceId *device_id_p);
ucs_status_t uct_gaudi_device_get(int device_index, synDeviceId *device_id_p);
void uct_gaudi_device_put(synDeviceId device_id);
void uct_gaudi_device_close(synDeviceId device_id);
int uct_gaudi_detect_devices(void);

/* Device info accessor functions */
const char* uct_gaudi_get_bus_id_by_index(int device_index);
unsigned int uct_gaudi_get_device_id_by_index(int device_index);
unsigned int uct_gaudi_get_module_id_by_index(int device_index);
ucs_sys_bus_id_t uct_gaudi_get_busid_from_cache(int gaudi_device, char *bus_id_str);

#endif /* UCT_GAUDI_DEVICE_REGISTRY_H */
