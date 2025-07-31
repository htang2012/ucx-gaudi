/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_ipc_cache.h"
#include "gaudi_ipc_iface.h"
#include <ucs/debug/log.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/profile/profile.h>
#include <ucs/sys/sys.h>
#include <ucs/sys/string.h>
#include <ucs/sys/ptr_arith.h>
#include <ucs/datastruct/khash.h>




typedef struct uct_gaudi_ipc_cache_hash_key {
    pid_t    pid;
} uct_gaudi_ipc_cache_hash_key_t;

static UCS_F_ALWAYS_INLINE int
uct_gaudi_ipc_cache_hash_equal(uct_gaudi_ipc_cache_hash_key_t key1,
                              uct_gaudi_ipc_cache_hash_key_t key2)
{
    return (key1.pid == key2.pid);
}

static UCS_F_ALWAYS_INLINE khint32_t
uct_gaudi_ipc_cache_hash_func(uct_gaudi_ipc_cache_hash_key_t key)
{
    return kh_int_hash_func(key.pid);
}

KHASH_INIT(gaudi_ipc_rem_cache, uct_gaudi_ipc_cache_hash_key_t,
           uct_gaudi_ipc_cache_t*, 1, uct_gaudi_ipc_cache_hash_func,
           uct_gaudi_ipc_cache_hash_equal);

typedef struct uct_gaudi_ipc_remote_cache {
    khash_t(gaudi_ipc_rem_cache) hash;
    ucs_recursive_spinlock_t    lock;
} uct_gaudi_ipc_remote_cache_t;

uct_gaudi_ipc_remote_cache_t uct_gaudi_ipc_remote_cache;

static ucs_pgt_dir_t *uct_gaudi_ipc_cache_pgt_dir_alloc(const ucs_pgtable_t *pgtable)
{
    void *ptr;
    int ret;

    ret = ucs_posix_memalign(&ptr,
                             ucs_max(sizeof(void *), UCS_PGT_ENTRY_MIN_ALIGN),
                             sizeof(ucs_pgt_dir_t), "gaudi_ipc_cache_pgdir");
    return (ret == 0) ? ptr : NULL;
}

static void uct_gaudi_ipc_cache_pgt_dir_release(const ucs_pgtable_t *pgtable,
                                               ucs_pgt_dir_t *dir)
{
    ucs_free(dir);
}

static void
uct_gaudi_ipc_cache_region_collect_callback(const ucs_pgtable_t *pgtable,
                                           ucs_pgt_region_t *pgt_region,
                                           void *arg)
{
    ucs_list_link_t *list = arg;
    uct_gaudi_ipc_cache_region_t *region;

    region = ucs_derived_of(pgt_region, uct_gaudi_ipc_cache_region_t);
    ucs_list_add_tail(list, &region->list);
}

static ucs_status_t
uct_gaudi_ipc_close_memhandle(uct_gaudi_ipc_cache_region_t *region)
{
    synStatus syn_status;

    syn_status = synDeviceFree(region->key.ph.src_device_id, region->key.ph.handle, 0);
    if (syn_status != synSuccess) {
        ucs_error("Failed to free device memory: %d", syn_status);
        return UCS_ERR_IO_ERROR;
    }

    return UCS_OK;
}

static void uct_gaudi_ipc_cache_purge(uct_gaudi_ipc_cache_t *cache)
{
    uct_gaudi_ipc_cache_region_t *region, *tmp;
    ucs_list_link_t region_list;

    ucs_list_head_init(&region_list);
    ucs_pgtable_purge(&cache->pgtable, uct_gaudi_ipc_cache_region_collect_callback,
                      &region_list);
    ucs_list_for_each_safe(region, tmp, &region_list, list) {
        uct_gaudi_ipc_close_memhandle(region);
        ucs_free(region);
    }
    ucs_trace("%s: gaudi ipc cache purged", cache->name);
}

static ucs_status_t
uct_gaudi_ipc_open_memhandle(uint64_t memh, void **mapped_addr)
{
    synStatus syn_status;

    syn_status = synDeviceMalloc(memh, 0, 0, 0, (uint64_t*)mapped_addr);
    if (syn_status != synSuccess) {
        ucs_error("Failed to allocate device memory: %d", syn_status);
        return UCS_ERR_NO_MEMORY;
    }

    return UCS_OK;
}

static void uct_gaudi_ipc_cache_invalidate_regions(uct_gaudi_ipc_cache_t *cache,
                                                  void *from, void *to)
{
    ucs_list_link_t region_list;
    ucs_status_t status;
    uct_gaudi_ipc_cache_region_t *region, *tmp;

    ucs_list_head_init(&region_list);
    ucs_pgtable_search_range(&cache->pgtable, (ucs_pgt_addr_t)from,
                             (ucs_pgt_addr_t)to - 1,
                             uct_gaudi_ipc_cache_region_collect_callback,
                             &region_list);
    ucs_list_for_each_safe(region, tmp, &region_list, list) {
        status = ucs_pgtable_remove(&cache->pgtable, &region->super);
        if (status != UCS_OK) {
            ucs_error("failed to remove address:%p from cache (%s)",
                      (void *)region->key.d_bptr, ucs_status_string(status));
        }

        status = uct_gaudi_ipc_close_memhandle(region);
        if (status != UCS_OK) {
            ucs_error("failed to close memhandle for base addr:%p (%s)",
                      (void *)region->key.d_bptr, ucs_status_string(status));
        }

        ucs_free(region);
    }
    ucs_trace("%s: closed memhandles in the range [%p..%p]",
              cache->name, from, to);
}

static ucs_status_t
uct_gaudi_ipc_get_remote_cache(pid_t pid, uct_gaudi_ipc_cache_t **cache)
{
    ucs_status_t status = UCS_OK;
    char target_name[64];
    uct_gaudi_ipc_cache_hash_key_t key;
    khiter_t khiter;
    int khret;

    ucs_recursive_spin_lock(&uct_gaudi_ipc_remote_cache.lock);

    key.pid = pid;

    khiter = kh_put(gaudi_ipc_rem_cache, &uct_gaudi_ipc_remote_cache.hash, key,
                    &khret);
    if ((khret == UCS_KH_PUT_BUCKET_EMPTY) ||
        (khret == UCS_KH_PUT_BUCKET_CLEAR)) {
        ucs_snprintf_safe(target_name, sizeof(target_name), "dest:%d",
                          key.pid);
        status = uct_gaudi_ipc_create_cache(cache, target_name);
        if (status != UCS_OK) {
            kh_del(gaudi_ipc_rem_cache, &uct_gaudi_ipc_remote_cache.hash, khiter);
            ucs_error("could not create create gaudi ipc cache: %s",
                      ucs_status_string(status));
            goto err_unlock;
        }

        kh_val(&uct_gaudi_ipc_remote_cache.hash, khiter) = *cache;
    } else if (khret == UCS_KH_PUT_KEY_PRESENT) {
        *cache = kh_val(&uct_gaudi_ipc_remote_cache.hash, khiter);
    } else {
        ucs_error("unable to use gaudi_ipc remote_cache hash");
        status = UCS_ERR_NO_RESOURCE;
    }
err_unlock:
    ucs_recursive_spin_unlock(&uct_gaudi_ipc_remote_cache.lock);
    return status;
}

ucs_status_t uct_gaudi_ipc_unmap_memhandle(pid_t pid, uintptr_t d_bptr,
                                          void *mapped_addr)
{
    ucs_status_t status = UCS_OK;
    uct_gaudi_ipc_cache_t *cache;
    ucs_pgt_region_t *pgt_region;
    uct_gaudi_ipc_cache_region_t *region;

    status = uct_gaudi_ipc_get_remote_cache(pid, &cache);
    if (status != UCS_OK) {
        return status;
    }

    /* use write lock because cache maybe modified */
    pthread_rwlock_wrlock(&cache->lock);
    pgt_region = UCS_PROFILE_CALL(ucs_pgtable_lookup, &cache->pgtable, d_bptr);
    ucs_assert(pgt_region != NULL);
    region = ucs_derived_of(pgt_region, uct_gaudi_ipc_cache_region_t);

    ucs_assert(region->refcount >= 1);
    region->refcount--;

    if (!region->refcount) {
        status = ucs_pgtable_remove(&cache->pgtable, &region->super);
        if (status != UCS_OK) {
            ucs_error("failed to remove address:%p from cache (%s)",
                      (void *)region->key.d_bptr, ucs_status_string(status));
        }
        ucs_assert(region->mapped_addr == mapped_addr);
        status = uct_gaudi_ipc_close_memhandle(region);
        ucs_free(region);
    }

    pthread_rwlock_unlock(&cache->lock);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_ipc_map_memhandle,
                 (key, mapped_addr),
                 uct_gaudi_ipc_rkey_t *key, void **mapped_addr)
{
    uct_gaudi_ipc_cache_t *cache;
    ucs_status_t status;
    ucs_pgt_region_t *pgt_region;
    uct_gaudi_ipc_cache_region_t *region;
    int ret;

    status = uct_gaudi_ipc_get_remote_cache(key->pid, &cache);
    if (status != UCS_OK) {
        return status;
    }

    pthread_rwlock_wrlock(&cache->lock);
    pgt_region = UCS_PROFILE_CALL(ucs_pgtable_lookup,
                                  &cache->pgtable, (uintptr_t)key->d_bptr);
    if (ucs_likely(pgt_region != NULL)) {
        region = ucs_derived_of(pgt_region, uct_gaudi_ipc_cache_region_t);

        if (key->ph.handle == region->key.ph.handle) {
            /*cache hit */
            ucs_trace("%s: gaudi_ipc cache hit addr:%p size:%lu region:"
                      UCS_PGT_REGION_FMT, cache->name, (void *)key->d_bptr,
                      key->b_len, UCS_PGT_REGION_ARG(&region->super));

            *mapped_addr = region->mapped_addr;
            ucs_assert(region->refcount < UINT64_MAX);
            region->refcount++;
            pthread_rwlock_unlock(&cache->lock);
            return UCS_OK;
        } else {
            ucs_trace("%s: gaudi_ipc cache remove stale region:"
                      UCS_PGT_REGION_FMT " new_addr:%p new_size:%lu",
                      cache->name, UCS_PGT_REGION_ARG(&region->super),
                      (void *)key->d_bptr, key->b_len);

            status = ucs_pgtable_remove(&cache->pgtable, &region->super);
            if (status != UCS_OK) {
                ucs_error("%s: failed to remove address:%p from cache",
                          cache->name, (void *)key->d_bptr);
                goto err;
            }

            /* close memhandle */
            uct_gaudi_ipc_close_memhandle(region);
            ucs_free(region);
        }
    }

    status = uct_gaudi_ipc_open_memhandle(key->ph.handle, mapped_addr);
    if (ucs_unlikely(status != UCS_OK)) {
        if (ucs_likely(status == UCS_ERR_ALREADY_EXISTS)) {
            /* unmap all overlapping regions and retry*/
            uct_gaudi_ipc_cache_invalidate_regions(cache, (void *)key->d_bptr,
                                                  UCS_PTR_BYTE_OFFSET(key->d_bptr,
                                                                      key->b_len));
            status = uct_gaudi_ipc_open_memhandle(key->ph.handle, mapped_addr);
            if (ucs_unlikely(status != UCS_OK)) {
                if (ucs_likely(status == UCS_ERR_ALREADY_EXISTS)) {
                    /* unmap all cache entries and retry */
                    uct_gaudi_ipc_cache_purge(cache);
                    status =
                        uct_gaudi_ipc_open_memhandle(key->ph.handle, mapped_addr);
                    if (status != UCS_OK) {
                        ucs_fatal("%s: failed to open ipc mem handle. addr:%p "
                                  "len:%lu (%s)", cache->name,
                                  (void *)key->d_bptr, key->b_len,
                                  ucs_status_string(status));
                    }
                } else {
                    ucs_fatal("%s: failed to open ipc mem handle. addr:%p len:%lu",
                              cache->name, (void *)key->d_bptr, key->b_len);
                }
            }
        } else {
            ucs_debug("%s: failed to open ipc mem handle. addr:%p len:%lu",
                      cache->name, (void *)key->d_bptr, key->b_len);
            goto err;
        }
    }

    /*create new cache entry */
    ret = ucs_posix_memalign((void **)&region,
                             ucs_max(sizeof(void *), UCS_PGT_ENTRY_MIN_ALIGN),
                             sizeof(uct_gaudi_ipc_cache_region_t),
                             "uct_gaudi_ipc_cache_region");
    if (ret != 0) {
        ucs_warn("failed to allocate uct_gaudi_ipc_cache region");
        status = UCS_ERR_NO_MEMORY;
        goto err;
    }

    region->super.start = ucs_align_down_pow2((uintptr_t)key->d_bptr,
                                               UCS_PGT_ADDR_ALIGN);
    region->super.end   = ucs_align_up_pow2  ((uintptr_t)key->d_bptr + key->b_len,
                                               UCS_PGT_ADDR_ALIGN);
    region->key         = *key;
    region->mapped_addr = *mapped_addr;
    region->refcount    = 1;
    region->channel_id  = key->channel_id;
    region->is_channel_mapped = false; /* Traditional handle mapping */

    status = UCS_PROFILE_CALL(ucs_pgtable_insert,
                              &cache->pgtable, &region->super);
    if (status == UCS_ERR_ALREADY_EXISTS) {
        /* overlapped region means memory freed at source. remove and try insert */
        uct_gaudi_ipc_cache_invalidate_regions(cache,
                                              (void *)region->super.start,
                                              (void *)region->super.end);
        status = UCS_PROFILE_CALL(ucs_pgtable_insert,
                                  &cache->pgtable, &region->super);
    }
    if (status != UCS_OK) {

        ucs_error("%s: failed to insert region:"UCS_PGT_REGION_FMT" size:%lu :%s",
                  cache->name, UCS_PGT_REGION_ARG(&region->super), key->b_len,
                  ucs_status_string(status));
        ucs_free(region);
        goto err;
    }

    ucs_trace("%s: gaudi_ipc cache new region:"UCS_PGT_REGION_FMT" size:%lu",
              cache->name, UCS_PGT_REGION_ARG(&region->super), key->b_len);

    status = UCS_OK;

err:
    pthread_rwlock_unlock(&cache->lock);
    return status;
}

ucs_status_t uct_gaudi_ipc_create_cache(uct_gaudi_ipc_cache_t **cache,
                                       const char *name)
{
    ucs_status_t status;
    uct_gaudi_ipc_cache_t *cache_desc;
    int ret;

    cache_desc = ucs_malloc(sizeof(uct_gaudi_ipc_cache_t), "uct_gaudi_ipc_cache_t");
    if (cache_desc == NULL) {
        ucs_error("failed to allocate memory for gaudi_ipc cache");
        return UCS_ERR_NO_MEMORY;
    }

    ret = pthread_rwlock_init(&cache_desc->lock, NULL);
    if (ret) {
        ucs_error("pthread_rwlock_init() failed: %m");
        status = UCS_ERR_INVALID_PARAM;
        goto err;
    }

    status = ucs_pgtable_init(&cache_desc->pgtable,
                              uct_gaudi_ipc_cache_pgt_dir_alloc,
                              uct_gaudi_ipc_cache_pgt_dir_release);
    if (status != UCS_OK) {
        goto err_destroy_rwlock;
    }

    cache_desc->name = strdup(name);
    if (cache_desc->name == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_destroy_rwlock;
    }

    *cache = cache_desc;
    return UCS_OK;

err_destroy_rwlock:
    pthread_rwlock_destroy(&cache_desc->lock);
err:
    free(cache_desc);
    return status;
}

void uct_gaudi_ipc_destroy_cache(uct_gaudi_ipc_cache_t *cache)
{
    uct_gaudi_ipc_cache_purge(cache);
    ucs_pgtable_cleanup(&cache->pgtable);
    pthread_rwlock_destroy(&cache->lock);
    free(cache->name);
    ucs_free(cache);
}

UCS_STATIC_INIT {
    ucs_recursive_spinlock_init(&uct_gaudi_ipc_remote_cache.lock, 0);
    kh_init_inplace(gaudi_ipc_rem_cache, &uct_gaudi_ipc_remote_cache.hash);
}

UCS_STATIC_CLEANUP {
    uct_gaudi_ipc_cache_t *rem_cache;

    kh_foreach_value(&uct_gaudi_ipc_remote_cache.hash, rem_cache, {
        uct_gaudi_ipc_destroy_cache(rem_cache);
    })
    kh_destroy_inplace(gaudi_ipc_rem_cache, &uct_gaudi_ipc_remote_cache.hash);
    ucs_recursive_spinlock_destroy(&uct_gaudi_ipc_remote_cache.lock);
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_ipc_map_memhandle_channel,
                 (key, mapped_addr, md),
                 uct_gaudi_ipc_rkey_t *key, void **mapped_addr, uct_gaudi_ipc_md_t *md)
{
    uct_gaudi_ipc_cache_t *cache;
    ucs_status_t status;
    ucs_pgt_region_t *pgt_region;
    uct_gaudi_ipc_cache_region_t *region;
    uint32_t channel_id;
    int ret;

    /* Check if we can use custom channels for node-local communication */
    if (!md || key->src_device_id >= md->device_count || 
        md->deviceIds[key->src_device_id] < 0) {
        /* Fallback to traditional IPC handle mapping */
        return uct_gaudi_ipc_map_memhandle(key, mapped_addr);
    }

    status = uct_gaudi_ipc_get_remote_cache(key->pid, &cache);
    if (status != UCS_OK) {
        return status;
    }

    pthread_rwlock_wrlock(&cache->lock);
    pgt_region = UCS_PROFILE_CALL(ucs_pgtable_lookup,
                                  &cache->pgtable, (uintptr_t)key->d_bptr);
    if (ucs_likely(pgt_region != NULL)) {
        region = ucs_derived_of(pgt_region, uct_gaudi_ipc_cache_region_t);

        if (key->channel_id == region->key.channel_id && region->is_channel_mapped) {
            /* Cache hit for channel-based mapping */
            ucs_trace("%s: gaudi_ipc channel cache hit addr:%p channel:%u region:"
                      UCS_PGT_REGION_FMT, cache->name, (void *)key->d_bptr,
                      key->channel_id, UCS_PGT_REGION_ARG(&region->super));

            *mapped_addr = region->mapped_addr;
            ucs_assert(region->refcount < UINT64_MAX);
            region->refcount++;
            pthread_rwlock_unlock(&cache->lock);
            return UCS_OK;
        }
    }

    /* Create or get the custom channel for this device pair */
    status = uct_gaudi_ipc_channel_create(md, key->src_device_id, key->dst_device_id, &channel_id);
    if (status != UCS_OK) {
        pthread_rwlock_unlock(&cache->lock);
        /* Fallback to traditional IPC */
        return uct_gaudi_ipc_map_memhandle(key, mapped_addr);
    }

    /* For custom channels, the "mapped_addr" is the same as the original device pointer */
    /* since we use direct device-to-device communication */
    *mapped_addr = key->d_bptr;

    /* Create new cache entry for channel-based mapping */
    ret = ucs_posix_memalign((void **)&region,
                             ucs_max(sizeof(void *), UCS_PGT_ENTRY_MIN_ALIGN),
                             sizeof(uct_gaudi_ipc_cache_region_t),
                             "uct_gaudi_ipc_cache_region");
    if (ret != 0) {
        ucs_warn("failed to allocate uct_gaudi_ipc_cache region");
        status = UCS_ERR_NO_MEMORY;
        goto err;
    }

    region->super.start = ucs_align_down_pow2((uintptr_t)key->d_bptr,
                                               UCS_PGT_ADDR_ALIGN);
    region->super.end   = ucs_align_up_pow2  ((uintptr_t)key->d_bptr + key->b_len,
                                               UCS_PGT_ADDR_ALIGN);
    region->key         = *key;
    region->mapped_addr = *mapped_addr;
    region->refcount    = 1;
    region->channel_id  = channel_id;
    region->is_channel_mapped = true; /* Using custom channel */

    status = UCS_PROFILE_CALL(ucs_pgtable_insert,
                              &cache->pgtable, &region->super);
    if (status == UCS_ERR_ALREADY_EXISTS) {
        /* Overlapped region - remove and try insert */
        uct_gaudi_ipc_cache_invalidate_regions(cache,
                                              (void *)region->super.start,
                                              (void *)region->super.end);
        status = UCS_PROFILE_CALL(ucs_pgtable_insert,
                                  &cache->pgtable, &region->super);
    }
    if (status != UCS_OK) {
        ucs_error("%s: failed to insert channel region:"UCS_PGT_REGION_FMT" size:%lu :%s",
                  cache->name, UCS_PGT_REGION_ARG(&region->super), key->b_len,
                  ucs_status_string(status));
        ucs_free(region);
        goto err;
    }

    ucs_trace("%s: gaudi_ipc channel cache new region:"UCS_PGT_REGION_FMT" size:%lu channel:%u",
              cache->name, UCS_PGT_REGION_ARG(&region->super), key->b_len, channel_id);

    status = UCS_OK;

err:
    pthread_rwlock_unlock(&cache->lock);
    return status;
}
