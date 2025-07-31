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
#include <habanalabs/synapse_api.h>
#include <habanalabs/synapse_api_types.h>
#include <habanalabs/synapse_common_types.h>
#include <hlml.h>

#define MAX_GAUDI_DEVICES 32
#define HLTHUNK_BUS_ID_MAX_LEN 64
#define BUS_ID_BUFFER_SIZE HLTHUNK_BUS_ID_MAX_LEN
#define HLML_MAX_DEVICES MAX_GAUDI_DEVICES

typedef struct uct_gaudi_device_info {
    synDeviceId deviceId;
    char bus_id[BUS_ID_BUFFER_SIZE];
    unsigned int moduleId;  // module Id is index in the Gaudi device array
} uct_gaudi_device_info_t;


typedef struct uct_gaudi_device {
    synDeviceId deviceId;  /* Synapse device ID, SYN_INVALID_DEVICE_ID if failed to acquire */
    synModuleId moduleId; /* Module ID, used for device identification */
    int         ref_count;
    bool        initialized; /* true if device has been successfully acquired */
} uct_gaudi_device_t;



static uct_gaudi_device_t uct_gaudi_devices[MAX_GAUDI_DEVICES];
/* static uct_gaudi_device_info_t uct_gaudi_device_info_cache[MAX_GAUDI_DEVICES]; */
static int uct_gaudi_cached_device_count = 0;
static pthread_mutex_t uct_gaudi_device_registry_mutex = PTHREAD_MUTEX_INITIALIZER;


ucs_status_t uct_gaudi_device_open(int moduleId, const char *bus_id_str, synDeviceId *deviceId_p)
{
    synStatus syn_status;
    
    if (moduleId < 0 || moduleId >= MAX_GAUDI_DEVICES) {
        return UCS_ERR_INVALID_PARAM;
    }

    /* Ensure device detection has been performed */
    uct_gaudi_detect_devices();

    pthread_mutex_lock(&uct_gaudi_device_registry_mutex);

    if (uct_gaudi_devices[moduleId].initialized) {
        if (uct_gaudi_devices[moduleId].deviceId != SYN_INVALID_DEVICE_ID) {
            uct_gaudi_devices[moduleId].ref_count++;
            *deviceId_p = uct_gaudi_devices[moduleId].deviceId;
            pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
            return UCS_OK;
        }
    } else {
        syn_status = synDeviceAcquireByModuleId(deviceId_p, moduleId);
        switch (syn_status) {
            case synSuccess:
                uct_gaudi_devices[moduleId].ref_count = 1;
                break;
            case synNoDeviceFound:
                ucs_debug("Gaudi device %d not found", moduleId);
                *deviceId_p = SYN_INVALID_DEVICE_ID;
                break;
            case synDeviceAlreadyAcquired:
                ucs_debug("Gaudi device %d already acquired", moduleId);
                uct_gaudi_devices[moduleId].ref_count++;
                *deviceId_p = uct_gaudi_devices[moduleId].deviceId;
                break;
            default:
                ucs_error("Failed to acquire Gaudi device %d: %d", moduleId, syn_status);
                uct_gaudi_devices[moduleId].initialized = true;
                uct_gaudi_devices[moduleId].deviceId = SYN_INVALID_DEVICE_ID;
                pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
                return UCS_ERR_NO_DEVICE;
        }
        uct_gaudi_devices[moduleId].initialized = true;
        uct_gaudi_devices[moduleId].deviceId = *deviceId_p;
        uct_gaudi_devices[moduleId].moduleId = moduleId;
    }

    pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
    return UCS_OK;
}

void uct_gaudi_device_put(synDeviceId deviceId)
{
    int i;

    pthread_mutex_lock(&uct_gaudi_device_registry_mutex);

    for (i = 0; i < uct_gaudi_cached_device_count; i++) {
        if (uct_gaudi_devices[i].deviceId == deviceId) {
            uct_gaudi_devices[i].ref_count--;
            if (uct_gaudi_devices[i].ref_count == 0) {
                synDeviceRelease(deviceId);
                uct_gaudi_devices[i].deviceId = SYN_INVALID_DEVICE_ID;
                uct_gaudi_devices[i].moduleId =  INVALID_MODULE_ID;
                uct_gaudi_devices[i].initialized = false;
            }
            break;
        }
    }

    pthread_mutex_unlock(&uct_gaudi_device_registry_mutex);
}




int uct_gaudi_detect_devices(void)
{
    static ucs_init_once_t uct_gaudi_init_once = UCS_INIT_ONCE_INITIALIZER;
    
    UCS_INIT_ONCE(&uct_gaudi_init_once) {
        synStatus status_syn;
        uint32_t device_count;
        
        ucs_debug("Detecting Gaudi devices...");
        status_syn = synDeviceGetCount(&device_count);
        if (status_syn != synSuccess) {
            uct_gaudi_cached_device_count = 0;
            return 0;
        }

        uct_gaudi_cached_device_count = device_count;
        
        /* Initialize device registry entries */
        for (int i = 0; i < device_count; i++) {
            uct_gaudi_devices[i].deviceId = SYN_INVALID_DEVICE_ID;
            uct_gaudi_devices[i].ref_count = 0;
            uct_gaudi_devices[i].initialized = false;
        }
        
        ucs_debug("Cached info for %d Gaudi devices", device_count);
    }
    
    return uct_gaudi_cached_device_count;
}