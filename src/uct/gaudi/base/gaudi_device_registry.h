/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_DEVICE_REGISTRY_H
#define UCT_GAUDI_DEVICE_REGISTRY_H

#include <ucs/type/status.h>
#include <ucs/sys/topo/base/topo.h>

ucs_status_t uct_gaudi_device_open(int device_index, const char *bus_id_str, int *fd_p);
ucs_status_t uct_gaudi_device_get(int device_index, int *fd_p);
void uct_gaudi_device_put(int fd);
void uct_gaudi_device_close(int fd);
int uct_gaudi_detect_devices(void);

/* Device info accessor functions */
const char* uct_gaudi_get_bus_id_by_index(int device_index);
unsigned int uct_gaudi_get_device_id_by_index(int device_index);
unsigned int uct_gaudi_get_module_id_by_index(int device_index);
ucs_sys_bus_id_t uct_gaudi_get_busid_from_cache(int gaudi_device, char *bus_id_str);

#endif /* UCT_GAUDI_DEVICE_REGISTRY_H */
