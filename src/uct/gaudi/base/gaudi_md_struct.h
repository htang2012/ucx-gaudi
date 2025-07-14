/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifndef UCT_GAUDI_MD_STRUCT_H
#define UCT_GAUDI_MD_STRUCT_H

#include <uct/base/uct_md.h>
#include <ucs/datastruct/list.h>
#include <ucs/type/spinlock.h>

/* Forward declarations */
BEGIN_C_DECLS

/* Gaudi memory handle structure */
typedef struct uct_gaudi_mem {
    ucs_list_link_t  list;             /* List link for memh_list */
    void            *address;          /* Base address */
    void            *vaddr;            /* Virtual address */
    size_t           length;           /* Memory length */
    size_t           size;             /* Memory size */
    uint64_t         reg_id;           /* Registration ID */
    uint64_t         handle;           /* Memory handle */
    int              dmabuf_fd;        /* DMA-BUF file descriptor */
    uint64_t         dmabuf_offset;    /* DMA-BUF offset */
    uint32_t         flags;            /* Memory flags */
    void            *bar_addr;         /* BAR mapped address */
    uint64_t         dev_addr;         /* Device address */
    int              is_mapped_memory; /* Whether memory is mapped */
} uct_gaudi_mem_t;

/* Gaudi key structure for memory key packing */
typedef struct uct_gaudi_key {
    uint64_t    vaddr;      /* Virtual address */
    size_t      length;     /* Memory length */
    int         dmabuf_fd;  /* DMA-BUF file descriptor */
    uint64_t    dev_addr;   /* Device address */
} uct_gaudi_key_t;

/* Gaudi error codes */
typedef enum {
    UCT_GAUDI_ERR_DEVICE_NOT_FOUND = -1001,
    UCT_GAUDI_ERR_OUT_OF_MEMORY = -1002,
    UCT_GAUDI_ERR_INVALID_PARAMS = -1003,
    UCT_GAUDI_ERR_DEVICE_BUSY = -1004,
    UCT_GAUDI_ERR_DMA_FAILED = -1005,
    UCT_GAUDI_ERR_TIMEOUT = -1006,
    UCT_GAUDI_ERR_PERMISSION_DENIED = -1007,
    UCT_GAUDI_ERR_CHANNEL_FAILED = -1008
} uct_gaudi_error_t;

/* Gaudi hardware info structure */
typedef struct uct_gaudi_hw_info {
    uint64_t    dram_base_address;    /* Base address of device memory */
    size_t      dram_size;            /* Size of device memory */
    uint64_t    sram_base_address;    /* Base address of SRAM */
    size_t      sram_size;            /* Size of SRAM */
} uct_gaudi_hw_info_t;

/* Gaudi IPC key structures */
typedef struct uct_gaudi_ipc_rkey {
    uint64_t    dev_addr;      /* Device address */
    size_t      length;        /* Memory length */
    int         dmabuf_fd;     /* DMA-BUF file descriptor */
    uint32_t    handle_id;     /* Handle ID */
} uct_gaudi_ipc_rkey_t;

typedef struct uct_gaudi_ipc_lkey {
    ucs_list_link_t  link;     /* List link */
    void            *d_bptr;   /* Device base pointer */
    size_t           b_len;    /* Buffer length */
    uint64_t         dev_addr; /* Device address */
    size_t           length;   /* Memory length */
    uint32_t         handle_id; /* Handle ID */
    struct {
        uint64_t     handle;        /* Memory handle */
        uint32_t     src_device_id; /* Source device ID */
        uint32_t     dst_device_id; /* Destination device ID */
        uint32_t     channel_id;    /* Channel ID */
        int          dmabuf_fd;     /* DMA-BUF file descriptor */
        size_t       dmabuf_size;   /* DMA-BUF size */
        uint64_t     dmabuf_offset; /* DMA-BUF offset */
    } ph;
} uct_gaudi_ipc_lkey_t;

typedef struct uct_gaudi_ipc_memh {
    ucs_list_link_t  list;       /* List of lkeys */
    void            *address;    /* Base address */
    size_t           length;     /* Memory length */
    uint32_t         flags;      /* Memory flags */
    uint32_t         dev_num;    /* Device number */
    uint32_t         channel_id; /* Channel ID */
} uct_gaudi_ipc_memh_t;

/* Gaudi statistics counters */
typedef enum {
    UCT_GAUDI_COPY_STAT_REG_CACHE_HITS,
    UCT_GAUDI_COPY_STAT_REG_CACHE_MISSES,
    UCT_GAUDI_COPY_STAT_DMABUF_EXPORTS,
    UCT_GAUDI_COPY_STAT_DMA_ERRORS,
    UCT_GAUDI_COPY_STAT_LAST
} uct_gaudi_copy_stat_t;

END_C_DECLS

#endif