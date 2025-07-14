/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_COPY_MD_H
#define UCT_GAUDI_COPY_MD_H

#include <uct/base/uct_md.h>
#include <uct/gaudi/base/gaudi_md.h>
#include <ucs/memory/memory_type.h>
#include <ucs/datastruct/list.h>
#include <ucs/type/spinlock.h>
#include <hlthunk.h>

/* Gaudi memory handle structure */
typedef struct uct_gaudi_mem {
    void *vaddr;        /* Virtual address */
    size_t size;        /* Size of the memory region */
    uint64_t handle;    /* Device memory handle */
    uint64_t dev_addr;  /* Device address */
    int dmabuf_fd;      /* DMA-BUF file descriptor */
    ucs_list_link_t list; /* List linkage for tracking */
} uct_gaudi_mem_t;

/* Gaudi remote key structure */
typedef struct uct_gaudi_key {
    uint64_t vaddr;     /* Virtual address */
    size_t length;      /* Length of the memory region */
    int dmabuf_fd;      /* DMA-BUF file descriptor */
} uct_gaudi_key_t;


extern uct_component_t uct_gaudi_copy_component;

/**
 * @brief gaudi_copy MD descriptor
 */
typedef struct uct_gaudi_copy_md {
    struct uct_md                super;           /* Domain info */
    int                          hlthunk_fd;      /* Habana Labs device file descriptor */
    int                          device_index;    /* Device index */
    struct {
        int                      dmabuf_supported; /* Whether DMA-BUF is supported */
    } config;
    struct hlthunk_hw_ip_info    hw_info;         /* Hardware information */
    char                        *device_type;     /* Device type string */
    ucs_list_link_t              memh_list;       /* List of allocated memory handles */
    ucs_recursive_spinlock_t     memh_lock;       /* Lock for memory handle list */
} uct_gaudi_copy_md_t;

/**
 * gaudi_copy MD configuration.
 */
typedef struct uct_gaudi_copy_md_config {
    uct_md_config_t             super;
    ucs_ternary_auto_value_t    enable_dmabuf;   /* Enable DMA-BUF support */
    ucs_on_off_auto_value_t     alloc_whole_reg; /* Register whole allocation */
    double                      max_reg_ratio;   /* Max registration ratio */
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

#endif
