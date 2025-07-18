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
#include <ucs/type/init_once.h>
#include <pthread.h>
#include <hlthunk.h>
#include <hlml.h>

#define MAX_GAUDI_DEVICES 32
#define HLTHUNK_BUS_ID_MAX_LEN 64
#define BUS_ID_BUFFER_SIZE HLTHUNK_BUS_ID_MAX_LEN
#define HLML_MAX_DEVICES MAX_GAUDI_DEVICES

typedef struct uct_gaudi_device_info {
    unsigned int device_id;
    char bus_id[BUS_ID_BUFFER_SIZE];
    unsigned int module_id;
} uct_gaudi_device_info_t;


typedef struct uct_gaudi_device {
    int         fd;         /* >0: valid fd, 0: not opened, -1: failed to open */
    int         ref_count;
} uct_gaudi_device_t;



static uct_gaudi_device_t uct_gaudi_devices[MAX_GAUDI_DEVICES];
static uct_gaudi_device_info_t uct_gaudi_device_info_cache[MAX_GAUDI_DEVICES];
static int uct_gaudi_cached_device_count = 0;
static pthread_mutex_t uct_gaudi_device_registry_mutex = PTHREAD_MUTEX_INITIALIZER;


ucs_status_t uct_gaudi_device_open(int device_index, const char *bus_id_str, int *fd_p)
{
    const char *cached_bus_id;
    
    if (device_index < 0 || device_index >= MAX_GAUDI_DEVICES) {
        return UCS_ERR_INVALID_PARAM;
    }

    /* Ensure device detection has been performed */
    uct_gaudi_detect_devices();

    /* Get cached bus_id if available, otherwise use provided one */
    cached_bus_id = uct_gaudi_get_bus_id_by_index(device_index);
    if (cached_bus_id == NULL) {
        cached_bus_id = bus_id_str;
    }

    pthread_mutex_lock(&uct_gaudi_device_registry_mutex);

    /* Check if device previously failed to open */
    if (uct_gaudi_devices[device_index].fd == -1) {
        pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
        return UCS_ERR_NO_DEVICE;
    }

    /* Check if device is already open and usable */
    if (uct_gaudi_devices[device_index].fd > 0) {
        uct_gaudi_devices[device_index].ref_count++;
        *fd_p = uct_gaudi_devices[device_index].fd;
        pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
        return UCS_OK;
    }

    *fd_p = hlthunk_open(device_index, cached_bus_id);
    if (*fd_p < 0) {
        ucs_warn("Failed to open hlthunk device %d (bus_id=%s)", device_index, cached_bus_id);
        /* Mark device as failed to prevent future retry attempts */
        uct_gaudi_devices[device_index].fd = -1;
        uct_gaudi_devices[device_index].ref_count = 0;
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

    bus_id = uct_gaudi_get_busid_from_cache(device_index, bus_id_str);
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
        if (uct_gaudi_devices[i].fd == fd && fd > 0) {
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


static int get_device_info(uct_gaudi_device_info_t *device_info, int *device_count_out)
{
    unsigned int device_count;
    unsigned int i;
    hlml_return_t hlml_ret;
    
    /* Initialize output parameter */
    *device_count_out = 0;
    
    /* Initialize HLML library */
    if ((hlml_ret = hlml_init()) != HLML_SUCCESS) {
        ucs_warn("Failed to initialize HLML library (error %d)", hlml_ret);
        return 1;
    }
    
    /* Get device count */
    if ((hlml_ret = hlml_device_get_count(&device_count)) != HLML_SUCCESS) {
        ucs_warn("Failed to get device count (error %d)", hlml_ret);
        hlml_shutdown();
        return 1;
    }
    
    /* Handle no devices case */
    if (device_count == 0) {
        ucs_debug("No Habana devices found");
        hlml_shutdown();
        return 0;
    }
    
    /* Limit devices to prevent buffer overflow */
    if (device_count > HLML_MAX_DEVICES) {
        ucs_warn("Found %u devices, limiting to %d", 
                device_count, HLML_MAX_DEVICES);
        device_count = HLML_MAX_DEVICES;
    }
    
    /* Collect device information */
    for (i = 0; i < device_count; i++) {
        hlml_device_t hlml_device;
        hlml_pci_info_t pci_info;
        
        /* Get device handle and PCI info in one check */
        if ((hlml_ret = hlml_device_get_handle_by_index(i, &hlml_device)) != HLML_SUCCESS ||
            (hlml_ret = hlml_device_get_pci_info(hlml_device, &pci_info)) != HLML_SUCCESS) {
            ucs_warn("Failed to get info for device %u (error %d)", i, hlml_ret);
            continue; /* Skip this device but continue with others */
        }
        
        /* Store device and bus ID in output array */
        device_info[i].device_id = pci_info.pci_device_id;
        strncpy(device_info[i].bus_id, pci_info.bus_id, BUS_ID_BUFFER_SIZE - 1);
        device_info[i].bus_id[BUS_ID_BUFFER_SIZE - 1] = '\0';
        
        /* Get module ID (optional, set to 0 if not available) */
        device_info[i].module_id = 0;
        hlml_ret = hlml_device_get_module_id(hlml_device, &device_info[i].module_id);
        if (hlml_ret != HLML_SUCCESS) {
            /* Module ID is optional, just log and continue */
            ucs_debug("Failed to get module ID for device %u (error %d), using 0", i, hlml_ret);
        }
    }
    
    *device_count_out = device_count;
    hlml_shutdown();
    return 0;
}

const char* uct_gaudi_get_bus_id_by_index(int device_index)
{
    if (device_index < 0 || device_index >= uct_gaudi_cached_device_count) {
        return NULL;
    }
    return uct_gaudi_device_info_cache[device_index].bus_id;
}

ucs_sys_bus_id_t uct_gaudi_get_busid_from_cache(int gaudi_device, char *bus_id_str)
{
    ucs_sys_bus_id_t bus_id = {-1, -1, -1, -1}; /* Initialize with invalid values */
    const char *cached_bus_id;
    int domain, bus_num, device, function;
    
    /* Get bus_id from cached device info */
    cached_bus_id = uct_gaudi_get_bus_id_by_index(gaudi_device);
    if (cached_bus_id == NULL) {
        ucs_debug("No cached bus_id for Gaudi device %d", gaudi_device);
        return bus_id;
    }
    
    /* Copy to output buffer */
    strncpy(bus_id_str, cached_bus_id, 64 - 1);
    bus_id_str[63] = '\0';
    
    /* Parse PCI bus ID string: format is [domain]:[bus]:[device].[function] */
    if (sscanf(cached_bus_id, "%x:%x:%x.%x", &domain, &bus_num, &device, &function) != 4) {
        ucs_debug("Failed to parse PCI bus ID '%s' for Gaudi device %d", 
                  cached_bus_id, gaudi_device);
        return bus_id;
    }

    /* Convert to UCX bus ID format */
    bus_id.domain   = domain;
    bus_id.bus      = bus_num;
    bus_id.slot     = device;
    bus_id.function = function;

    ucs_debug("Successfully parsed cached bus ID for Gaudi device %d (PCI: %s, domain=%d, bus=%d, slot=%d, func=%d)", 
              gaudi_device, cached_bus_id, domain, bus_num, device, function);
    
    return bus_id;
}

unsigned int uct_gaudi_get_device_id_by_index(int device_index)
{
    if (device_index < 0 || device_index >= uct_gaudi_cached_device_count) {
        return 0;
    }
    return uct_gaudi_device_info_cache[device_index].device_id;
}

unsigned int uct_gaudi_get_module_id_by_index(int device_index)
{
    if (device_index < 0 || device_index >= uct_gaudi_cached_device_count) {
        return 0;
    }
    return uct_gaudi_device_info_cache[device_index].module_id;
}


int uct_gaudi_detect_devices(void)
{
    static ucs_init_once_t uct_gaudi_init_once = UCS_INIT_ONCE_INITIALIZER;
    
    UCS_INIT_ONCE(&uct_gaudi_init_once) {
        int device_count;
        int i;
        
        ucs_debug("Detecting Gaudi devices...");
        if (get_device_info(uct_gaudi_device_info_cache, &device_count) != 0) {
            uct_gaudi_cached_device_count = 0;
            continue;
        }

        uct_gaudi_cached_device_count = device_count;
        
        /* Initialize device registry entries */
        for (i = 0; i < device_count; i++) {
            uct_gaudi_devices[i].fd = 0;
            uct_gaudi_devices[i].ref_count = 0;
        }
        
        ucs_debug("Cached info for %d Gaudi devices", device_count);
    }
    
    return uct_gaudi_cached_device_count;
}