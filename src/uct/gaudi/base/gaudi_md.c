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
#include <cjson/cJSON.h>


ucs_sys_bus_id_t uct_gaudi_get_busid_from_env(int gaudi_device, char *bus_id_str)
{
    ucs_sys_bus_id_t bus_id = {-1, -1, -1, -1}; /* Initialize with invalid values */
    char pci_bus_id_str[64] = {0};
    int domain, bus_num, device, function;
    cJSON *table, *entry;
    
    const char *mapping_env = getenv("GAUDI_MAPPING_TABLE");
    if (!mapping_env) {
        ucs_debug("GAUDI_MAPPING_TABLE env not set for Gaudi device %d", gaudi_device);
        return bus_id;
    }
    
    table = cJSON_Parse(mapping_env);
    if (!table || !cJSON_IsArray(table)) {
        ucs_debug("GAUDI_MAPPING_TABLE: Invalid JSON array");
        if (table) cJSON_Delete(table);
        return bus_id;
    }
    
    entry = NULL;
    cJSON_ArrayForEach(entry, table) {
        cJSON *index = cJSON_GetObjectItem(entry, "index");
        cJSON *bus_id_json = cJSON_GetObjectItem(entry, "bus_id");
        if (cJSON_IsNumber(index) && index->valueint == gaudi_device && cJSON_IsString(bus_id_json)) {
            strncpy(pci_bus_id_str, bus_id_json->valuestring, sizeof(pci_bus_id_str)-1);
            pci_bus_id_str[sizeof(pci_bus_id_str)-1] = '\0';
            break;
        }
    }
    cJSON_Delete(table);
    
    if (pci_bus_id_str[0] == '\0') {
        ucs_debug("GAUDI_MAPPING_TABLE: No bus_id for Gaudi device %d", gaudi_device);
        return bus_id;
    }

    ucs_snprintf_safe(bus_id_str, 64, "%s", pci_bus_id_str);

    /* Parse PCI bus ID string: format is [domain]:[bus]:[device].[function] */
    if (sscanf(pci_bus_id_str, "%x:%x:%x.%x", &domain, &bus_num, &device, &function) != 4) {
        ucs_debug("Failed to parse PCI bus ID '%s' for Gaudi device %d", 
                  pci_bus_id_str, gaudi_device);
        return bus_id;
    }

    /* Convert to UCX bus ID format */
    bus_id.domain   = domain;
    bus_id.bus      = bus_num;
    bus_id.slot     = device;
    bus_id.function = function;

    ucs_debug("Successfully parsed bus ID for Gaudi device %d (PCI: %s, domain=%d, bus=%d, slot=%d, func=%d)", 
              gaudi_device, pci_bus_id_str, domain, bus_num, device, function);
    
    return bus_id;
}


void uct_gaudi_base_get_sys_dev(int gaudi_dev,
                               ucs_sys_device_t *sys_dev_p)
{
    ucs_sys_bus_id_t bus_id_info;
    ucs_status_t status;
    char bus_id_buffer[64];
    
    /* Get bus ID from environment */
    bus_id_info = uct_gaudi_get_busid_from_env(gaudi_dev, bus_id_buffer);
    if (bus_id_info.domain == -1) {
        ucs_debug("System device detection failed for Gaudi device %d, will use unknown", gaudi_dev);
        *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
        return;
    }

    /* Find the system device by PCI bus ID */
    status = ucs_topo_find_device_by_bus_id(&bus_id_info, sys_dev_p);
    if (status != UCS_OK) {
        ucs_debug("Failed to find system device by PCI bus ID for Gaudi device %d: %s", 
                  gaudi_dev, ucs_status_string(status));
        *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
        return;
    }

    /* Associate the system device with the Gaudi device index */
    status = ucs_topo_sys_device_set_user_value(*sys_dev_p, gaudi_dev);
    if (status != UCS_OK) {
        ucs_debug("Failed to set user value for system device for Gaudi device %d: %s", 
                  gaudi_dev, ucs_status_string(status));
        *sys_dev_p = UCS_SYS_DEVICE_ID_UNKNOWN;
        return;
    }

    ucs_debug("Successfully mapped Gaudi device %d to system device (domain=%d, bus=%d, slot=%d, func=%d)", 
              gaudi_dev, bus_id_info.domain, bus_id_info.bus, bus_id_info.slot, bus_id_info.function);
}

ucs_status_t
uct_gaudi_base_get_gaudi_device(ucs_sys_device_t sys_dev, int *dev_ptr)
{
    uintptr_t user_value;

    user_value = ucs_topo_sys_device_get_user_value(sys_dev);
    if (user_value == UINTPTR_MAX) {
        return UCS_ERR_NO_DEVICE;
    }

    *dev_ptr = user_value;
    if (*dev_ptr == -1) {
        return UCS_ERR_NO_DEVICE;
    }

    return UCS_OK;
}

int uct_gaudi_get_count_from_env(void)
{
    const char *env_mapping = getenv("GAUDI_MAPPING_TABLE");
    int device_count = 0;
    cJSON *json_table;
    
    if (!env_mapping) {
        ucs_debug("GAUDI_MAPPING_TABLE env not set, no Gaudi devices available");
        return 0;
    }
    
    json_table = cJSON_Parse(env_mapping);
    if (!json_table || !cJSON_IsArray(json_table)) {
        ucs_debug("GAUDI_MAPPING_TABLE: Invalid JSON array");
        if (json_table) cJSON_Delete(json_table);
        return 0;
    }
    
    device_count = cJSON_GetArraySize(json_table);
    cJSON_Delete(json_table);
    
    ucs_debug("Found %d Gaudi devices in GAUDI_MAPPING_TABLE", device_count);
    return device_count;
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

    /* Get Gaudi device count from environment */
    num_gpus = uct_gaudi_get_count_from_env();
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
        ucs_snprintf_safe(resources[i].md_name, sizeof(resources[i].md_name),
                          "gaudi:%d", i);
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