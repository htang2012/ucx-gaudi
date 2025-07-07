/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifndef UCT_GAUDI_MD_H
#define UCT_GAUDI_MD_H

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>


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

#endif /* UCT_GAUDI_MD_H */
