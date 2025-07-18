/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_COPY_MD_H
#define UCT_GAUDI_COPY_MD_H

#include <uct/base/uct_md.h>
#include <uct/gaudi/base/gaudi_md.h>
#include <ucs/memory/memory_type.h>
#include <ucs/memory/rcache.h>
#include <ucs/datastruct/list.h>
#include <ucs/type/spinlock.h>
#include <ucs/stats/stats.h>
#include <hlthunk.h>

/* Gaudi memory handle structure */
typedef struct uct_gaudi_mem {
    void *vaddr;        /* Virtual address */
    size_t size;        /* Size of the memory region */
    uint64_t handle;    /* Device memory handle */
    uint64_t dev_addr;  /* Device address */
    int dmabuf_fd;      /* DMA-BUF file descriptor */
    uint64_t dmabuf_offset; /* Offset within DMA-BUF (for mapped memory) */
    uint8_t is_mapped_memory; /* Whether this is mapped device memory */
    ucs_list_link_t list; /* List linkage for tracking */
} uct_gaudi_mem_t;

/* Gaudi remote key structure */
typedef struct uct_gaudi_key {
    uint64_t vaddr;     /* Virtual address */
    size_t length;      /* Length of the memory region */
    int dmabuf_fd;      /* DMA-BUF file descriptor */
} uct_gaudi_key_t;

/* Registration cache region structure */
typedef struct uct_gaudi_copy_rcache_region {
    ucs_rcache_region_t  super;
    uct_gaudi_mem_t      memh;      /* Memory handle */
} uct_gaudi_copy_rcache_region_t;

/* Error codes for enhanced error handling */
typedef enum {
    UCT_GAUDI_ERR_DEVICE_NOT_FOUND    = -1,
    UCT_GAUDI_ERR_OUT_OF_MEMORY       = -2,
    UCT_GAUDI_ERR_INVALID_PARAMS      = -3,
    UCT_GAUDI_ERR_DEVICE_BUSY         = -4,
    UCT_GAUDI_ERR_DMA_FAILED          = -5,
    UCT_GAUDI_ERR_TIMEOUT             = -6,
    UCT_GAUDI_ERR_PERMISSION_DENIED   = -7,
    UCT_GAUDI_ERR_CHANNEL_FAILED      = -8
} uct_gaudi_error_t;

/* Statistics definitions */
enum {
    UCT_GAUDI_COPY_STAT_REG_CACHE_HITS,
    UCT_GAUDI_COPY_STAT_REG_CACHE_MISSES,
    UCT_GAUDI_COPY_STAT_DMABUF_EXPORTS,
    UCT_GAUDI_COPY_STAT_DMA_ERRORS,
    UCT_GAUDI_COPY_STAT_LAST
};

extern uct_component_t uct_gaudi_copy_component;

/**
 * @brief gaudi_copy MD descriptor
 */
typedef struct uct_gaudi_copy_md {
    struct uct_md                super;           /* Domain info */
    int                          hlthunk_fd;      /* Habana Labs device file descriptor */
    int                          device_index;    /* Device index */
    
    /* Registration cache components */
    ucs_rcache_t                *rcache;          /* Registration cache */
    ucs_linear_func_t           reg_cost;         /* Cost estimation */
    
    struct {
        int                      dmabuf_supported; /* Whether DMA-BUF is supported */
        int                      mapped_dmabuf_supported; /* Enhanced DMA-BUF with offset */
        int                      nic_ports_available; /* NIC ports for scale-out */
        ucs_ternary_auto_value_t enable_rcache;   /* Enable cache */
        double                   max_reg_ratio;   /* Max registration ratio */
        ucs_on_off_auto_value_t  alloc_whole_reg; /* Register whole allocation */
        ucs_ternary_auto_value_t enable_hw_block_access; /* Direct hardware access */
    } config;
    
    struct hlthunk_hw_ip_info    hw_info;         /* Hardware information */
    char                        *device_type;     /* Device type string */
    ucs_list_link_t              memh_list;       /* List of allocated memory handles */
    ucs_recursive_spinlock_t     memh_lock;       /* Lock for memory handle list */
#ifdef ENABLE_STATS
    ucs_stats_node_t            *stats;           /* Statistics */
#endif
} uct_gaudi_copy_md_t;

/**
 * gaudi_copy MD configuration.
 */
typedef struct uct_gaudi_copy_md_config {
    uct_md_config_t             super;
    ucs_ternary_auto_value_t    enable_dmabuf;   /* Enable DMA-BUF support */
    ucs_on_off_auto_value_t     alloc_whole_reg; /* Register whole allocation */
    double                      max_reg_ratio;   /* Max registration ratio */
    ucs_ternary_auto_value_t    enable_rcache;   /* Enable registration cache */
    ucs_rcache_config_t         rcache;          /* Registration cache config */
    ucs_time_t                  reg_cost;        /* Registration cost estimation */
    ucs_ternary_auto_value_t    enable_mapped_dmabuf; /* Enhanced DMA-BUF with offset */
    ucs_ternary_auto_value_t    enable_hw_block_access; /* Hardware block access */
    ucs_ternary_auto_value_t    enable_nic_scale_out; /* NIC-based scale-out */
} uct_gaudi_copy_md_config_t;

ucs_status_t uct_gaudi_copy_md_detect_memory_type(uct_md_h md,
                                                 const void *address,
                                                 size_t length,
                                                 ucs_memory_type_t *mem_type_p);

ucs_status_t uct_gaudi_copy_mem_reg(uct_md_h md, void *address, size_t length,
                                   const uct_md_mem_reg_params_t *params, 
                                   uct_mem_h *memh_p);

ucs_status_t uct_gaudi_copy_mem_dereg(uct_md_h md, 
                                     const uct_md_mem_dereg_params_t *params);

ucs_status_t uct_gaudi_copy_mem_alloc(uct_md_h md, size_t *length_p,
                                     void **address_p, ucs_memory_type_t mem_type,
                                     ucs_sys_device_t sys_dev, unsigned flags, 
                                     const char *alloc_name, uct_mem_h *memh_p);

ucs_status_t uct_gaudi_copy_mem_free(uct_md_h md, uct_mem_h memh);

ucs_status_t uct_gaudi_copy_mkey_pack(uct_md_h md, uct_mem_h memh, void *address,
                                     size_t length, const uct_md_mkey_pack_params_t *params,
                                     void *mkey_buffer);

/* Enhanced error handling functions */
const char* uct_gaudi_error_string(int error_code);
ucs_status_t uct_gaudi_translate_error(int hlthunk_error);

/* Registration cache functions */
ucs_status_t uct_gaudi_copy_rcache_mem_reg(uct_md_h md, void *address, size_t length,
                                          const uct_md_mem_reg_params_t *params, 
                                          uct_mem_h *memh_p);

ucs_status_t uct_gaudi_copy_rcache_mem_dereg(uct_md_h md, 
                                            const uct_md_mem_dereg_params_t *params);

/* DMA-BUF based device-to-device IPC functions */
ucs_status_t uct_gaudi_copy_export_dmabuf(uct_md_h md, void *address, size_t length,
                                         int *dmabuf_fd, uint64_t *dmabuf_offset);

ucs_status_t uct_gaudi_copy_import_dmabuf(uct_md_h md, int dmabuf_fd, size_t length,
                                         uint64_t offset, uint64_t *device_va);

ucs_status_t uct_gaudi_copy_unmap_dmabuf(uct_md_h md, uint64_t device_va);

#endif
