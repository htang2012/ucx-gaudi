/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_MD_H
#define UCT_GAUDI_MD_H

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <ucs/memory/memory_type.h>
#include <ucs/datastruct/list.h>
#include <ucs/type/spinlock.h>
#include <hlthunk.h>


#define UCT_MD_MEM_REG_FIELD_GAUDI_FD UCS_BIT(16)

 typedef struct uct_gaudi_memh {
        int gaudi_fd;
        uint64_t gaudi_handle;
        uint64_t device_va;
        int dmabuf_fd;
        size_t length;
        void *host_ptr;
    } uct_gaudi_memh_t;



typedef struct uct_gaudi_mem_reg_params {
    uct_md_mem_reg_params_t super; // Must be first
    int gaudi_fd;
} uct_gaudi_mem_reg_params_t;
/**
 * Get the bus ID for a given Gaudi device from environment.
 *
 * @param [in]  gaudi_device     Gaudi device index.
 *
 * @return Bus ID structure, or all fields set to -1 if not found.
 */
ucs_sys_bus_id_t uct_gaudi_get_busid_from_env(int gaudi_device, char *bus_id_str);
int uct_gaudi_get_count_from_env(void);

/**
 * Get the system device for a given Gaudi device.
 *
 * @param [in]  gaudi_device     Gaudi device index.
 * @param [out] sys_dev_p        System device identifier.
 */
void uct_gaudi_base_get_sys_dev(int gaudi_device,
                               ucs_sys_device_t *sys_dev_p);

/**
 * Get the Gaudi device for a given system device.
 *
 * @param [in]  sys_dev          System device identifier.
 * @param [out] device           Gaudi device index.
 *
 * @return UCS_OK if successful, or UCS_ERR_NO_DEVICE if not found.
 */
ucs_status_t
uct_gaudi_base_get_gaudi_device(ucs_sys_device_t sys_dev, int *device);

/**
 * Query the list of available Gaudi memory domains.
 *
 * @param [in]  component        Component to query.
 * @param [out] resources_p      List of available memory domains.
 * @param [out] num_resources_p  Number of available memory domains.
 *
 * @return UCS_OK if successful, or UCS_ERR_NO_MEMORY if failed to allocate the
 *         array of memory domain resources.
 */
ucs_status_t
uct_gaudi_base_query_md_resources(uct_component_t *component,
                                 uct_md_resource_desc_t **resources_p,
                                 unsigned *num_resources_p);



/*
 * Gaudi memory registration now uses standard UCX memory registration and attribute structures.
 * All DMA-BUF and device handle information is communicated via uct_md_mem_reg_params_t and
 * uct_md_mem_attr_t. Provider-specific state is kept private in the implementation.
 */

ucs_status_t uct_gaudi_md_mem_reg(uct_md_h md, void *address, size_t length,
                                  const uct_md_mem_reg_params_t *params, uct_mem_h *memh_p);

int uct_gaudi_md_open_device(int device_index);

#endif /* UCT_GAUDI_MD_H */
