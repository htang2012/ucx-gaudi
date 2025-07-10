/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_DMA_H
#define UCT_GAUDI_DMA_H

#include <ucs/type/status.h>
#include <stdint.h>
#include <stddef.h>

/* Forward declare hlthunk structures */
struct hlthunk_hw_ip_info;

/* DMA direction constants */
enum uct_gaudi_dma_direction {
    UCT_GAUDI_DMA_HOST_TO_DRAM = 0,  /* DMA_DIR_HOST_TO_DRAM */
    UCT_GAUDI_DMA_HOST_TO_SRAM = 1,  /* DMA_DIR_HOST_TO_SRAM */
    UCT_GAUDI_DMA_DRAM_TO_SRAM = 2,  /* DMA_DIR_DRAM_TO_SRAM */
    UCT_GAUDI_DMA_SRAM_TO_DRAM = 3,  /* DMA_DIR_SRAM_TO_DRAM */
    UCT_GAUDI_DMA_SRAM_TO_HOST = 4,  /* DMA_DIR_SRAM_TO_HOST */
    UCT_GAUDI_DMA_DRAM_TO_HOST = 5,  /* DMA_DIR_DRAM_TO_HOST */
    UCT_GAUDI_DMA_DRAM_TO_DRAM = 6,  /* DMA_DIR_DRAM_TO_DRAM */
    UCT_GAUDI_DMA_SRAM_TO_SRAM = 7   /* DMA_DIR_SRAM_TO_SRAM */
};

/**
 * @brief Execute DMA copy operation using hlthunk command buffers
 * 
 * @param hlthunk_fd    File descriptor for hlthunk device
 * @param dst           Destination address
 * @param src           Source address  
 * @param length        Transfer length
 * @param hw_info       Hardware info for device detection (can be NULL for auto-detect)
 * 
 * @return UCS_OK on success, error status otherwise
 */
ucs_status_t uct_gaudi_dma_execute_copy(int hlthunk_fd, void *dst, void *src, 
                                       size_t length, 
                                       const struct hlthunk_hw_ip_info *hw_info);

/**
 * @brief Execute DMA copy with automatic hlthunk device management
 * Opens and closes hlthunk device automatically
 * 
 * @param dst           Destination address
 * @param src           Source address  
 * @param length        Transfer length
 * 
 * @return UCS_OK on success, error status otherwise
 */
ucs_status_t uct_gaudi_dma_execute_copy_auto(int hlthunk_fd, void *dst, void *src, size_t length);

#endif /* UCT_GAUDI_DMA_H */
