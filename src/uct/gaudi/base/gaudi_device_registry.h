/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_DEVICE_REGISTRY_H
#define UCT_GAUDI_DEVICE_REGISTRY_H

#include <ucs/type/status.h>

ucs_status_t uct_gaudi_device_open(int device_index, const char *bus_id_str, int *fd_p);
ucs_status_t uct_gaudi_device_get(int device_index, int *fd_p);
void uct_gaudi_device_put(int fd);
void uct_gaudi_device_close(int fd);

#endif /* UCT_GAUDI_DEVICE_REGISTRY_H */
