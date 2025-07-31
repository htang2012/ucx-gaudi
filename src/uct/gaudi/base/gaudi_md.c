/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_md.h"
#include "gaudi_iface.h"
#include "gaudi_device_registry.h"

#include <ucs/sys/module.h>
#include <ucs/sys/string.h>
#include <ucs/sys/topo/base/topo.h>
#include <synapse_api.h>
#include <errno.h>




ucs_status_t
uct_gaudi_base_query_md_resources(uct_component_t *component,
                                 uct_md_resource_desc_t **resources_p,
                                 unsigned *num_resources_p)
{
    const unsigned sys_device_priority = 10;
    uct_md_resource_desc_t *resources;
    ucs_sys_device_t sys_dev;
    ucs_status_t status;
    char device_name[10];
    int i;
    uint32_t num_gpus;
    synStatus status_syn;

    status_syn = synInitialize();
    if (status_syn != synSuccess) {
        ucs_error("Failed to initialize Synapse: %d", status_syn);
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }

    status_syn = synDeviceGetCount(&num_gpus);
    if (status_syn != synSuccess) {
        ucs_error("Failed to get Gaudi device count from Synapse: %d", status_syn);
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }

    if (num_gpus <= 0) {
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }



    for (i = 0; i < num_gpus; ++i) {
        uct_gaudi_base_get_sys_dev(i, &sys_dev);
        if (sys_dev != UCS_SYS_DEVICE_ID_UNKNOWN) {
            ucs_snprintf_safe(device_name, sizeof(device_name), "GAUDI_%d", i);
            status = ucs_topo_sys_device_set_name(sys_dev, device_name, sys_device_priority);
            ucs_assert_always(status == UCS_OK);
        } else {
            ucs_debug("Gaudi device %d is not mapped to a system device", i);
        }
    }

    ucs_debug("Found %u Gaudi devices", num_gpus);

    resources = ucs_calloc(num_gpus, sizeof(uct_md_resource_desc_t),
                           "gaudi md resources");
    if (NULL == resources) {
        ucs_error("Failed to allocate Gaudi MD resources");
        return UCS_ERR_NO_MEMORY;
    }

    for (i = 0; i < num_gpus; ++i) {
        ucs_snprintf_safe(resources[i].md_name, sizeof(resources[i].md_name),
                          "gaudi_%d", i);
    }
    *resources_p = resources;
    *num_resources_p = num_gpus;

    return UCS_OK;
}

ucs_status_t  ucs_topo_bus_id_from_str(const char *str, ucs_sys_bus_id_t *bus_id_p)
{
    if (str == NULL || bus_id_p == NULL) {
        ucs_error("Invalid input: str=%p, bus_id_p=%p", str, bus_id_p);
        return UCS_ERR_INVALID_PARAM;
    }
    ucs_info("Parsing bus ID from string: %s", str);
    sscanf(str, "%02hhx:%02hhx.%hhd", &bus_id_p->bus, &bus_id_p->slot, &bus_id_p->function);

    bus_id_p->domain = 0; // Default domain for simplicity
    return UCS_OK;
}



void uct_gaudi_base_get_sys_dev(int gaudi_dev,
                               ucs_sys_device_t *sys_dev_p)
{
    synStatus status_syn;
    char bus_id_buffer[64];
    ucs_status_t status;
    ucs_sys_bus_id_t bus_id; /* Move declaration before any code for C90 compliance */

    status_syn = synDeviceGetPCIBusId(bus_id_buffer, sizeof(bus_id_buffer), gaudi_dev);
    if (status_syn != synSuccess) {
        ucs_debug("Failed to get PCI bus ID for Gaudi device %d: %d", gaudi_dev, status_syn);
        *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
        return;
    }

    status = ucs_topo_bus_id_from_str(bus_id_buffer, &bus_id);
    if (status != UCS_OK) {
        ucs_debug("Failed to parse PCI bus ID string for Gaudi device %d: %s",
                  gaudi_dev, ucs_status_string(status));
        *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
        return;
    }

    status = ucs_topo_find_device_by_bus_id(&bus_id, sys_dev_p);
    if (status != UCS_OK) {
        ucs_debug("Failed to find system device by PCI bus ID for Gaudi device %d: %s",
                  gaudi_dev, ucs_status_string(status));
        *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
        return;
    }

    status = ucs_topo_sys_device_set_user_value(*sys_dev_p, gaudi_dev);
    if (status != UCS_OK) {
        ucs_debug("Failed to set user value for system device for Gaudi device %d: %s",
                  gaudi_dev, ucs_status_string(status));
        *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
        return;
    }

    ucs_debug("Successfully mapped Gaudi device %d to system device", gaudi_dev);
}


UCS_STATIC_INIT
{
    synInitialize();
}

UCS_STATIC_CLEANUP
{
}

UCS_MODULE_INIT() {
    UCS_MODULE_FRAMEWORK_DECLARE(uct_gaudi);
    UCS_MODULE_FRAMEWORK_LOAD(uct_gaudi, 0);
    return UCS_OK;
}