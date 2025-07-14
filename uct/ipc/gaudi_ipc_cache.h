/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifndef UCT_GAUDI_IPC_CACHE_H_
#define UCT_GAUDI_IPC_CACHE_H_

#include <ucs/datastruct/pgtable.h>
#include <ucs/datastruct/list.h>
#include <ucs/type/init_once.h>
#include <ucs/type/spinlock.h>
#include "gaudi_ipc_md.h"


typedef struct uct_gaudi_ipc_cache        uct_gaudi_ipc_cache_t;
typedef struct uct_gaudi_ipc_cache_region uct_gaudi_ipc_cache_region_t;
typedef struct uct_gaudi_ipc_rem_memh     uct_gaudi_ipc_rem_memh_t;


struct uct_gaudi_ipc_cache_region {
    ucs_pgt_region_t        super;
    ucs_list_link_t         list;
    uct_gaudi_ipc_rkey_t     key;
    void                    *mapped_addr;
    uint64_t                refcount;
    uint32_t                channel_id;       /* Associated custom channel */
    bool                    is_channel_mapped; /* Whether using channel mapping */
};


struct uct_gaudi_ipc_cache {
    pthread_rwlock_t      lock;
    ucs_pgtable_t         pgtable;
    char                  *name;
};


ucs_status_t uct_gaudi_ipc_create_cache(uct_gaudi_ipc_cache_t **cache,
                                       const char *name);


void uct_gaudi_ipc_destroy_cache(uct_gaudi_ipc_cache_t *cache);


ucs_status_t
uct_gaudi_ipc_map_memhandle(uct_gaudi_ipc_rkey_t *key, void **mapped_addr);

ucs_status_t
uct_gaudi_ipc_map_memhandle_channel(uct_gaudi_ipc_rkey_t *key, void **mapped_addr,
                                    uct_gaudi_ipc_md_t *md);

ucs_status_t uct_gaudi_ipc_unmap_memhandle(pid_t pid, uintptr_t d_bptr,
                                          void *mapped_addr);

#endif
