/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_dma.h"
#include <ucs/debug/log.h>
#include <sys/mman.h>
#include <string.h>

/* Synapse API */
#include <habanalabs/synapse_api.h>
#include <habanalabs/synapse_api_types.h>
#include <habanalabs/synapse_common_types.h>

/**
 * @brief Determine if an address is device memory based on device properties
 */
static bool uct_gaudi_dma_is_device_memory(void *addr, synDeviceId device_id)
{
    uintptr_t addr_val = (uintptr_t)addr;
    synDeviceInfo device_info;
    synStatus status;
    
    if (device_id == SYN_INVALID_DEVICE_ID) {
        /* For IPC or when device_id is not available, assume device memory if address is high */
        return (addr_val > 0x100000000UL); /* > 4GB typically indicates device memory */
    }
    
    /* Get device information from Synapse API */
    status = synDeviceGetInfo(device_id, &device_info);
    if (status != synSuccess) {
        /* Fallback to address-based detection */
        return (addr_val > 0x100000000UL);
    }
    
    /* Check if address is in device memory range */
    if (addr_val >= device_info.dramBaseAddress && 
        addr_val < (device_info.dramBaseAddress + device_info.dramSize)) {
        return true;
    }
    
    if (addr_val >= device_info.sramBaseAddress && 
        addr_val < (device_info.sramBaseAddress + device_info.sramSize)) {
        return true;
    }
    
    return false;
}

/**
 * @brief Determine DMA direction based on source and destination memory types
 */
static enum uct_gaudi_dma_direction 
uct_gaudi_dma_get_direction(bool src_is_device, bool dst_is_device)
{
    if (src_is_device && dst_is_device) {
        return UCT_GAUDI_DMA_DRAM_TO_DRAM;
    } else if (!src_is_device && dst_is_device) {
        return UCT_GAUDI_DMA_HOST_TO_DRAM;
    } else if (src_is_device && !dst_is_device) {
        return UCT_GAUDI_DMA_DRAM_TO_HOST;
    } else {
        /* Host to host - not supported by DMA */
        return UCT_GAUDI_DMA_DRAM_TO_DRAM; /* Fallback */
    }
}

/**
 * @brief Execute the actual DMA operation using Synapse API
 */
static ucs_status_t uct_gaudi_dma_execute_operation(synDeviceId device_id, 
                                                   uint64_t src_dev_addr,
                                                   uint64_t dst_dev_addr,
                                                   size_t length,
                                                   enum uct_gaudi_dma_direction dma_dir)
{
    synStatus status;
    synStreamHandle stream_handle;
    
    /* Create a stream for the operation */
    status = synStreamCreateGeneric(&stream_handle, device_id, 0);
    if (status != synSuccess) {
        ucs_debug("Failed to create Synapse stream: %d", status);
        return UCS_ERR_NO_RESOURCE;
    }
    
    /* Execute DMA operation based on direction */
    switch (dma_dir) {
        case UCT_GAUDI_DMA_HOST_TO_DRAM:
            status = synMemCopyAsync(stream_handle, src_dev_addr, length, 
                                   dst_dev_addr, HOST_TO_DRAM);
            break;
        case UCT_GAUDI_DMA_DRAM_TO_HOST:
            status = synMemCopyAsync(stream_handle, src_dev_addr, length, 
                                   dst_dev_addr, DRAM_TO_HOST);
            break;
        case UCT_GAUDI_DMA_DRAM_TO_DRAM:
            status = synMemCopyAsync(stream_handle, src_dev_addr, length, 
                                   dst_dev_addr, DRAM_TO_DRAM);
            break;
        default:
            ucs_debug("Unsupported DMA direction: %d", dma_dir);
            synStreamDestroy(stream_handle);
            return UCS_ERR_UNSUPPORTED;
    }
    
    if (status != synSuccess) {
        ucs_debug("Synapse DMA operation failed: %d", status);
        synStreamDestroy(stream_handle);
        return UCS_ERR_IO_ERROR;
    }
    
    /* Wait for completion */
    status = synStreamSynchronize(stream_handle);
    if (status != synSuccess) {
        ucs_debug("Synapse stream synchronization failed: %d", status);
        synStreamDestroy(stream_handle);
        return UCS_ERR_IO_ERROR;
    }
    
    ucs_trace("Gaudi DMA copy completed: src=0x%lx -> dst=0x%lx, len=%zu",
              src_dev_addr, dst_dev_addr, length);
    
    /* Clean up */
    synStreamDestroy(stream_handle);
    
    return UCS_OK;
}

ucs_status_t uct_gaudi_dma_execute_copy(synDeviceId device_id, void *dst, void *src, 
                                       size_t length)
{
    ucs_status_t status = UCS_OK;
    uint64_t src_dev_addr = 0, dst_dev_addr = 0;
    enum uct_gaudi_dma_direction dma_dir;
    bool src_is_device, dst_is_device;
    
    if (device_id == SYN_INVALID_DEVICE_ID) {
        ucs_debug("Invalid Synapse device ID");
        return UCS_ERR_INVALID_PARAM;
    }
    
    if (length == 0) {
        return UCS_OK;
    }
    
    /* Determine memory types */
    src_is_device = uct_gaudi_dma_is_device_memory(src, device_id);
    dst_is_device = uct_gaudi_dma_is_device_memory(dst, device_id);
    
    /* Get DMA direction */
    dma_dir = uct_gaudi_dma_get_direction(src_is_device, dst_is_device);
    
    /* Set up addresses and map host memory if needed */
    if (src_is_device && dst_is_device) {
        /* Device to device - no mapping needed */
        src_dev_addr = (uint64_t)src;
        dst_dev_addr = (uint64_t)dst;
    } else if (!src_is_device && dst_is_device) {
        /* Host to device: use host memory directly for Synapse API */
        src_dev_addr = (uint64_t)src;
        dst_dev_addr = (uint64_t)dst;
    } else if (src_is_device && !dst_is_device) {
        /* Device to host: use host memory directly for Synapse API */
        src_dev_addr = (uint64_t)src;
        dst_dev_addr = (uint64_t)dst;
    } else {
        /* Host to host - not supported by DMA, use memcpy */
        ucs_debug("Host to host DMA not supported, using memcpy instead");
        memcpy(dst, src, length);
        return UCS_OK;
    }
    
    /* Execute DMA operation using Synapse API */
    status = uct_gaudi_dma_execute_operation(device_id, src_dev_addr, dst_dev_addr, 
                                             length, dma_dir);
    
    return status;
}