/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_device_registry.h"
#include "gaudi_md.h"
#include <ucs/debug/log.h>
#include <pthread.h>
#include <hlthunk.h>

#define MAX_GAUDI_DEVICES 32
#define HLTHUNK_BUS_ID_MAX_LEN 64

typedef struct uct_gaudi_device {
    int         fd;
    int         ref_count;
} uct_gaudi_device_t;

static uct_gaudi_device_t uct_gaudi_devices[MAX_GAUDI_DEVICES];
static pthread_mutex_t uct_gaudi_device_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

ucs_status_t uct_gaudi_device_open(int device_index, const char *bus_id_str, int *fd_p)
{
    if (device_index < 0 || device_index >= MAX_GAUDI_DEVICES) {
        return UCS_ERR_INVALID_PARAM;
    }

    pthread_mutex_lock(&uct_gaudi_device_registry_mutex);

    if (uct_gaudi_devices[device_index].fd > 0) {
        uct_gaudi_devices[device_index].ref_count++;
        *fd_p = uct_gaudi_devices[device_index].fd;
        pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
        return UCS_OK;
    }

    *fd_p = hlthunk_open(device_index, bus_id_str);
    if (*fd_p < 0) {
        ucs_warn("Failed to open hlthunk device %d (bus_id=%s)", device_index, bus_id_str);
        pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
        return UCS_ERR_NO_DEVICE;
    }

    uct_gaudi_devices[device_index].fd = *fd_p;
    uct_gaudi_devices[device_index].ref_count = 1;

    pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
    return UCS_OK;
}

ucs_status_t uct_gaudi_device_get(int device_index, int *fd_p)
{
    char bus_id_str[HLTHUNK_BUS_ID_MAX_LEN];
    ucs_sys_bus_id_t bus_id;

    bus_id = uct_gaudi_get_busid_from_env(device_index, bus_id_str);
    if (bus_id.domain == -1) {
        return UCS_ERR_NO_DEVICE;
    }

    return uct_gaudi_device_open(device_index, bus_id_str, fd_p);
}

void uct_gaudi_device_put(int fd)
{
    int i;

    pthread_mutex_lock(&uct_gaudi_device_registry_mutex);

    for (i = 0; i < MAX_GAUDI_DEVICES; i++) {
        if (uct_gaudi_devices[i].fd == fd) {
            uct_gaudi_devices[i].ref_count--;
            if (uct_gaudi_devices[i].ref_count == 0) {
                hlthunk_close(uct_gaudi_devices[i].fd);
                uct_gaudi_devices[i].fd = 0;
            }
            break;
        }
    }

    pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
}

void uct_gaudi_device_close(int fd)
{
    uct_gaudi_device_put(fd);
}