/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_md.h"
#include "gaudi_iface.h"

#include <ucs/sys/module.h>
#include <ucs/sys/string.h>
#include <hlthunk.h>


void uct_gaudi_base_get_sys_dev(int gaudi_device,
                               ucs_sys_device_t *sys_dev_p)
{
    // ucs_sys_bus_id_t bus_id;
    // ucs_status_t status;
    // struct hlthunk_pci_bdf pci_bdf;

    // if (hlthunk_get_pci_bdf(gaudi_device, &pci_bdf)) {
    //     goto err;
    // }

    // bus_id.domain   = pci_bdf.domain;
    // bus_id.bus      = pci_bdf.bus;
    // bus_id.slot     = pci_bdf.device;
    // bus_id.function = pci_bdf.function;

    // status = ucs_topo_find_device_by_bus_id(&bus_id, sys_dev_p);
    // if (status != UCS_OK) {
    //     goto err;
    // }

    // status = ucs_topo_sys_device_set_user_value(*sys_dev_p, gaudi_device);
    // if (status != UCS_OK) {
    //     goto err;
    // }

    // return;

// err:
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
    ucs_sys_device_t sys_dev;
    ucs_status_t status;
    char device_name[10];
    int i, num_gpus;

    num_gpus = hlthunk_get_device_count(HLTHUNK_DEVICE_GAUDI);

    if (num_gpus < 0) {
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }

    for (i = 0; i < num_gpus; ++i) {
        uct_gaudi_base_get_sys_dev(i, &sys_dev);
        if (sys_dev == UCS_SYS_DEVICE_ID_UNKNOWN) {
            continue;
        }

        ucs_snprintf_safe(device_name, sizeof(device_name), "GAUDI%d", i);
        status = ucs_topo_sys_device_set_name(sys_dev, device_name,
                                              sys_device_priority);
        ucs_assert_always(status == UCS_OK);
    }

    return uct_md_query_single_md_resource(component, resources_p,
                                           num_resources_p);
}

UCS_MODULE_INIT() {
    UCS_MODULE_FRAMEWORK_DECLARE(uct_gaudi);
    UCS_MODULE_FRAMEWORK_LOAD(uct_gaudi, 0);
    return UCS_OK;
}