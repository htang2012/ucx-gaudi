/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_DMA_H
#define UCT_GAUDI_DMA_H

#include <ucs/type/status.h>
#include <stdint.h>
#include <stddef.h>
#include <habanalabs/synapse_api.h>

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
 * @brief Execute DMA copy operation using synapse API
 * 
 * @param device_id     Synapse device ID
 * @param dst           Destination address
 * @param src           Source address  
 * @param length        Transfer length
 * 
 * @return UCS_OK on success, error status otherwise
 */
ucs_status_t uct_gaudi_dma_execute_copy(synDeviceId device_id, void *dst, void *src, 
                                       size_t length);

/**
 * @brief Execute DMA copy with automatic device management
 * Acquires and releases synapse device automatically
 * 
 * @param dst           Destination address
 * @param src           Source address  
 * @param length        Transfer length
 * 
 * @return UCS_OK on success, error status otherwise
 */
ucs_status_t uct_gaudi_dma_execute_copy_auto(void *dst, void *src, size_t length);

#endif /* UCT_GAUDI_DMA_H */
