/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_md.h"
#include "gaudi_iface.h"

#include <ucs/sys/module.h>
#include <ucs/sys/string.h>
#include <ucs/sys/topo/base/topo.h>
#include <hlthunk.h>
#include <errno.h>


void uct_gaudi_base_get_sys_dev(int gaudi_device,
                               ucs_sys_device_t *sys_dev_p)
{
    ucs_sys_bus_id_t bus_id;
    ucs_status_t status;
    char pci_bus_id_str[64];
    int domain, bus, device, function;
    int fd;

    /* Open the Gaudi control device by device ID */
    fd = hlthunk_open_control(gaudi_device, NULL);
    if (fd < 0) {
        ucs_debug("Failed to open Gaudi control device %d: %s", 
                  gaudi_device, strerror(errno));
        goto err;
    }

    /* Get PCI bus ID as string */
    if (hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id_str, sizeof(pci_bus_id_str)) != 0) {
        ucs_debug("Failed to get PCI bus ID for Gaudi device %d", gaudi_device);
        hlthunk_close(fd);
        goto err;
    }
    
    hlthunk_close(fd);

    /* Parse PCI bus ID string: format is [domain]:[bus]:[device].[function] */
    if (sscanf(pci_bus_id_str, "%x:%x:%x.%x", &domain, &bus, &device, &function) != 4) {
        ucs_debug("Failed to parse PCI bus ID '%s' for Gaudi device %d", 
                  pci_bus_id_str, gaudi_device);
        goto err;
    }

    /* Convert to UCX bus ID format */
    bus_id.domain   = domain;
    bus_id.bus      = bus;
    bus_id.slot     = device;
    bus_id.function = function;

    /* Find the system device by PCI bus ID */
    status = ucs_topo_find_device_by_bus_id(&bus_id, sys_dev_p);
    if (status != UCS_OK) {
        ucs_debug("Failed to find system device by PCI bus ID %s for Gaudi device %d: %s", 
                  pci_bus_id_str, gaudi_device, ucs_status_string(status));
        goto err;
    }

    /* Associate the system device with the Gaudi device index */
    status = ucs_topo_sys_device_set_user_value(*sys_dev_p, gaudi_device);
    if (status != UCS_OK) {
        ucs_debug("Failed to set user value for system device for Gaudi device %d: %s", 
                  gaudi_device, ucs_status_string(status));
        goto err;
    }

    ucs_debug("Successfully mapped Gaudi device %d to system device (PCI: %s, domain=%d, bus=%d, slot=%d, func=%d)", 
              gaudi_device, pci_bus_id_str, domain, bus, device, function);
    return;

err:
    ucs_debug("System device detection failed for Gaudi device %d, will use unknown", gaudi_device);
    *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
}

ucs_status_t
uct_gaudi_base_get_gaudi_device(ucs_sys_device_t sys_dev, int *device)
{
    uintptr_t user_value;

    user_value = ucs_topo_sys_device_get_user_value(sys_dev);
    if (user_value == UINTPTR_MAX) {
        return UCS_ERR_NO_DEVICE;
    }

    *device = user_value;
    if (*device == -1) {
        return UCS_ERR_NO_DEVICE;
    }

    return UCS_OK;
}

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
    int i, num_gpus;

    /* Try different Gaudi device types */
    num_gpus = hlthunk_get_device_count(HLTHUNK_DEVICE_DONT_CARE);
    if (num_gpus <= 0) {
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }

    for (i = 0; i < num_gpus; ++i) {
        uct_gaudi_base_get_sys_dev(i, &sys_dev);
        if (sys_dev != UCS_SYS_DEVICE_ID_UNKNOWN) {
            ucs_snprintf_safe(device_name, sizeof(device_name), "GAUDI%d", i);
            status = ucs_topo_sys_device_set_name(sys_dev, device_name,
                                                  sys_device_priority);
            ucs_assert_always(status == UCS_OK);
        } else {
            ucs_debug("System device detection failed for Gaudi device %d, "
                      "transport will still be available but device name will be unknown", i);
        }
    }

    ucs_debug("Successfully detected Gaudi devices");
    resources = calloc(num_gpus, sizeof(*resources));
    if (resources == NULL) {
        ucs_error("Failed to allocate memory for Gaudi MD resources");
        return UCS_ERR_NO_MEMORY;
    }

    for (i = 0; i < num_gpus; ++i) {
        snprintf(resources[i].md_name, sizeof(resources[i].md_name),
                 "gaudi%d", i);
    }
    *num_resources_p = num_gpus;
    *resources_p = resources;
    return UCS_OK;

}

UCS_MODULE_INIT() {
    UCS_MODULE_FRAMEWORK_DECLARE(uct_gaudi);
    UCS_MODULE_FRAMEWORK_LOAD(uct_gaudi, 0);
    return UCS_OK;
}