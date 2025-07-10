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

/* Habana Labs driver */
#include <hlthunk.h>

/**
 * @brief Determine if an address is device memory based on hardware info
 */
static bool uct_gaudi_dma_is_device_memory(void *addr, const struct hlthunk_hw_ip_info *hw_info)
{
    uintptr_t addr_val = (uintptr_t)addr;
    
    if (hw_info) {
        /* Check if address is in DRAM range */
        if (addr_val >= hw_info->dram_base_address && 
            addr_val < (hw_info->dram_base_address + hw_info->dram_size)) {
            return true;
        }
        
        /* Check if address is in SRAM range */
        if (addr_val >= hw_info->sram_base_address && 
            addr_val < (hw_info->sram_base_address + hw_info->sram_size)) {
            return true;
        }
    }
    
    /* For IPC or when hw_info is not available, assume device memory if address is high */
    return (addr_val > 0x100000000UL); /* > 4GB typically indicates device memory */
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

ucs_status_t uct_gaudi_dma_execute_copy(int hlthunk_fd, void *dst, void *src, 
                                       size_t length, 
                                       const struct hlthunk_hw_ip_info *hw_info)
{
    ucs_status_t status = UCS_OK;
    uint64_t src_dev_addr = 0, dst_dev_addr = 0;
    enum uct_gaudi_dma_direction dma_dir;
    bool src_is_device, dst_is_device;
    bool need_unmap_src = false, need_unmap_dst = false;
    
    if (hlthunk_fd < 0) {
        ucs_debug("Invalid hlthunk file descriptor");
        return UCS_ERR_INVALID_PARAM;
    }
    
    if (length == 0) {
        return UCS_OK;
    }
    
    /* Determine memory types */
    src_is_device = uct_gaudi_dma_is_device_memory(src, hw_info);
    dst_is_device = uct_gaudi_dma_is_device_memory(dst, hw_info);
    
    /* Get DMA direction */
    dma_dir = uct_gaudi_dma_get_direction(src_is_device, dst_is_device);
    
    /* Set up addresses and map host memory if needed */
    if (src_is_device && dst_is_device) {
        /* Device to device - no mapping needed */
        src_dev_addr = (uint64_t)src;
        dst_dev_addr = (uint64_t)dst;
    } else if (!src_is_device && dst_is_device) {
        /* Host to device: map source host memory */
        src_dev_addr = hlthunk_host_memory_map(hlthunk_fd, src, 0, length);
        if (src_dev_addr == 0) {
            ucs_debug("Failed to map source host memory for DMA");
            return UCS_ERR_NO_MEMORY;
        }
        need_unmap_src = true;
        dst_dev_addr = (uint64_t)dst;
    } else if (src_is_device && !dst_is_device) {
        /* Device to host: map destination host memory */
        dst_dev_addr = hlthunk_host_memory_map(hlthunk_fd, dst, 0, length);
        if (dst_dev_addr == 0) {
            ucs_debug("Failed to map destination host memory for DMA");
            return UCS_ERR_NO_MEMORY;
        }
        need_unmap_dst = true;
        src_dev_addr = (uint64_t)src;
    } else {
        /* Host to host - not supported by DMA */
        ucs_debug("Host to host DMA not supported, use memcpy instead");
        return UCS_ERR_UNSUPPORTED;
    }
    
    /* Execute DMA operation */
    {
        uint64_t cb_handle = 0;
        void *cb_ptr = NULL;
        int rc;
        
        /* Create command buffer using hl-thunk high-level API */
        rc = hlthunk_request_command_buffer(hlthunk_fd, 4096, &cb_handle);
        if (rc == 0 && cb_handle != 0) {
            /* Map command buffer to user space */
            cb_ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, 
                         hlthunk_fd, cb_handle);
            if (cb_ptr != MAP_FAILED) {
                /* Use hlthunk's simplified DMA approach */
                struct hlthunk_cs_in cs_in = {0};
                struct hlthunk_cs_out cs_out = {0};
                
                /* Basic linear DMA packet structure (simplified) */
                struct {
                    uint32_t opcode;      /* DMA opcode and direction */
                    uint32_t reserved0;
                    uint64_t src_addr;    /* Source address */
                    uint64_t dst_addr;    /* Destination address */
                    uint32_t size;        /* Transfer size */
                    uint32_t reserved[3];
                } __attribute__((packed)) *dma_pkt = cb_ptr;
                
                /* Build DMA packet */
                memset(dma_pkt, 0, sizeof(*dma_pkt));
                dma_pkt->opcode = 0x11 | (dma_dir << 8);  /* LIN_DMA base opcode + direction */
                dma_pkt->src_addr = src_dev_addr;
                dma_pkt->dst_addr = dst_dev_addr;
                dma_pkt->size = length;
                
                /* Submit command buffer */
                cs_in.chunks_execute = &cb_handle;
                cs_in.num_chunks_execute = 1;
                cs_in.flags = 0;
                
                rc = hlthunk_command_submission(hlthunk_fd, &cs_in, &cs_out);
                if (rc == 0) {
                    ucs_trace("Gaudi DMA copy: src=0x%lx -> dst=0x%lx, len=%zu, seq=%lu",
                              src_dev_addr, dst_dev_addr, length, cs_out.seq);
                } else {
                    ucs_debug("Gaudi DMA command submission failed: %d", rc);
                    status = UCS_ERR_IO_ERROR;
                }
                
                munmap(cb_ptr, 4096);
            } else {
                ucs_debug("Failed to map Gaudi command buffer");
                status = UCS_ERR_NO_MEMORY;
            }
            
            hlthunk_destroy_command_buffer(hlthunk_fd, cb_handle);
        } else {
            ucs_debug("Failed to create Gaudi command buffer");
            status = UCS_ERR_NO_RESOURCE;
        }
    }
    
    /* Cleanup: unmap host memory if we mapped it */
    if (need_unmap_src && src_dev_addr != 0) {
        hlthunk_memory_unmap(hlthunk_fd, src_dev_addr);
    }
    if (need_unmap_dst && dst_dev_addr != 0) {
        hlthunk_memory_unmap(hlthunk_fd, dst_dev_addr);
    }
    
    return status;
}

