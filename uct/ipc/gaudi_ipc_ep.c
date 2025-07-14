/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_ipc_ep.h"
#include "gaudi_ipc_iface.h"
#include "gaudi_ipc_md.h"
#include "gaudi_ipc.inl"

#include <uct/base/uct_log.h>
#include <uct/base/uct_iov.inl>
#include <uct/gaudi/base/gaudi_dma.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/sys/math.h>
#include <ucs/type/class.h>
#include <ucs/profile/profile.h>

#define UCT_GAUDI_IPC_PUT 0
#define UCT_GAUDI_IPC_GET 1


static UCS_CLASS_INIT_FUNC(uct_gaudi_ipc_ep_t, const uct_ep_params_t *params)
{
    uct_gaudi_ipc_iface_t *iface = ucs_derived_of(params->iface,
                                                 uct_gaudi_ipc_iface_t);

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);
    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super.super);

    self->remote_pid = *(const pid_t*)params->iface_addr;
    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_gaudi_ipc_ep_t)
{
}

UCS_CLASS_DEFINE(uct_gaudi_ipc_ep_t, uct_base_ep_t)
UCS_CLASS_DEFINE_NEW_FUNC(uct_gaudi_ipc_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_gaudi_ipc_ep_t, uct_ep_t);

#define uct_gaudi_ipc_trace_data(_addr, _rkey, _fmt, ...)     \
    ucs_trace_data(_fmt " to %"PRIx64"(%+ld)", ## __VA_ARGS__, (_addr), (_rkey))

int uct_gaudi_ipc_ep_is_connected(const uct_ep_h tl_ep,
                                 const uct_ep_is_connected_params_t *params)
{
    const uct_gaudi_ipc_ep_t *ep = ucs_derived_of(tl_ep, uct_gaudi_ipc_ep_t);

    if (!uct_base_ep_is_connected(tl_ep, params)) {
        return 0;
    }

    return ep->remote_pid == *(pid_t*)params->iface_addr;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_gaudi_ipc_post_gaudi_async_copy(uct_ep_h tl_ep, uint64_t remote_addr,
                                  const uct_iov_t *iov, uct_rkey_t rkey,
                                  uct_completion_t *comp, int direction)
{
    uct_gaudi_ipc_unpacked_rkey_t *key = (uct_gaudi_ipc_unpacked_rkey_t *)rkey;
    uct_gaudi_ipc_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_gaudi_ipc_iface_t);
    uct_gaudi_ipc_md_t *md = ucs_derived_of(iface->super.super.md, uct_gaudi_ipc_md_t);
    void *mapped_rem_addr;
    void *mapped_addr;
    ucs_status_t status;
    void *dst, *src;
    size_t offset;

    if (ucs_unlikely(0 == iov[0].length)) {
        ucs_trace_data("Zero length request: skip it");
        return UCS_OK;
    }

    /* Try custom channel mapping first for node-local communication */
    status = uct_gaudi_ipc_map_memhandle_channel(&key->super, &mapped_addr, md);
    if (ucs_unlikely(status != UCS_OK)) {
        /* Fallback to traditional IPC handle mapping */
        status = uct_gaudi_ipc_map_memhandle(&key->super, &mapped_addr);
        if (ucs_unlikely(status != UCS_OK)) {
            goto out;
        }
    }

    offset          = (uintptr_t)remote_addr - (uintptr_t)key->super.d_bptr;
    mapped_rem_addr = (void *) ((uintptr_t) mapped_addr + offset);
    ucs_assert(offset <= key->super.b_len);

    dst = (direction == UCT_GAUDI_IPC_PUT) ? mapped_rem_addr : iov[0].buffer;
    src = (direction == UCT_GAUDI_IPC_PUT) ? iov[0].buffer : mapped_rem_addr;

    /* Use custom channel copy if available and channel ID is valid */
    if (key->super.channel_id != 0 && md && md->device_count > 0) {
        status = uct_gaudi_ipc_channel_copy(md, key->super.channel_id, dst, src, iov[0].length);
        if (status == UCS_OK) {
            ucs_trace("Gaudi IPC: Used custom channel %u for copy", key->super.channel_id);
            goto out;
        }
        /* Fall through to DMA copy if channel copy fails */
    }

    /* Implement proper DMA copy using shared utility function */
    status = uct_gaudi_dma_execute_copy_auto(dst, src, iov[0].length);
    if (status != UCS_OK) {
        ucs_debug("DMA copy failed, falling back to memcpy: %s", 
                  ucs_status_string(status));
        memcpy(dst, src, iov[0].length);
        status = UCS_OK;
    }

out:
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_ipc_ep_get_zcopy,
                 (tl_ep, iov, iovcnt, remote_addr, rkey, comp),
                 uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                 uint64_t remote_addr, uct_rkey_t rkey,
                 uct_completion_t *comp)
{
    ucs_status_t status;

    status = uct_gaudi_ipc_post_gaudi_async_copy(tl_ep, remote_addr, iov,
                                               rkey, comp, UCT_GAUDI_IPC_GET);
    if (UCS_STATUS_IS_ERR(status)) {
        return status;
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), GET, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    uct_gaudi_ipc_trace_data(remote_addr, rkey, "GET_ZCOPY [length %zu]",
                            uct_iov_total_length(iov, iovcnt));
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_ipc_ep_put_zcopy,
                 (tl_ep, iov, iovcnt, remote_addr, rkey, comp),
                 uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                 uint64_t remote_addr, uct_rkey_t rkey,
                 uct_completion_t *comp)
{
    ucs_status_t status;

    status = uct_gaudi_ipc_post_gaudi_async_copy(tl_ep, remote_addr, iov,
                                               rkey, comp, UCT_GAUDI_IPC_PUT);
    if (UCS_STATUS_IS_ERR(status)) {
        return status;
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), PUT, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    uct_gaudi_ipc_trace_data(remote_addr, rkey, "PUT_ZCOPY [length %zu]",
                                uct_iov_total_length(iov, iovcnt));
    return status;
}
