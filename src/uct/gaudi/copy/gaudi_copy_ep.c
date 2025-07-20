/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_copy_ep.h"
#include "gaudi_copy_iface.h"
#include "gaudi_copy_md.h"

#include <uct/base/uct_log.h>
#include <uct/base/uct_iov.inl>
#include <uct/gaudi/base/gaudi_md.h>
#include <uct/gaudi/base/gaudi_dma.h>
#include <ucs/profile/profile.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/sys/math.h>
#include <ucs/type/class.h>
#include <ucs/memory/memtype_cache.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


static UCS_CLASS_INIT_FUNC(uct_gaudi_copy_ep_t, const uct_ep_params_t *params)
{
    uct_gaudi_copy_iface_t *iface = ucs_derived_of(params->iface,
                                                  uct_gaudi_copy_iface_t);

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);
    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super.super);

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_gaudi_copy_ep_t)
{
}

UCS_CLASS_DEFINE(uct_gaudi_copy_ep_t, uct_base_ep_t)
UCS_CLASS_DEFINE_NEW_FUNC(uct_gaudi_copy_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_gaudi_copy_ep_t, uct_ep_t);

#define uct_gaudi_copy_trace_data(_name, _remote_addr, _iov, _iovcnt) \
    ucs_trace_data("%s [ptr %p len %zu] to 0x%" PRIx64, _name, (_iov)->buffer, \
                   (_iov)->length, (_remote_addr))

ucs_status_t
uct_gaudi_copy_post_gaudi_async_copy(uct_ep_h tl_ep, void *dst, void *src,
                                   size_t length, uct_completion_t *comp)
{
   
    /* Access hlthunk_fd from the Gaudi MD via iface->super.md */
    uct_gaudi_copy_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_gaudi_copy_iface_t);
    uct_md_h md = iface->super.super.md;
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    int hlthunk_fd = gaudi_md->hlthunk_fd;
    if (!length) {
        return UCS_OK;
    } else {
        return uct_gaudi_dma_execute_copy(hlthunk_fd, dst, src, length, NULL);
    }
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_copy_ep_get_short,
                 (tl_ep, buffer, length, remote_addr, rkey),
                 uct_ep_h tl_ep, void *buffer, unsigned length,
                 uint64_t remote_addr, uct_rkey_t rkey)
{
    ucs_status_t status;

    status = uct_gaudi_copy_post_gaudi_async_copy(tl_ep, buffer,
                                                (void *)remote_addr,
                                                length, NULL);
    if (!UCS_STATUS_IS_ERR(status)) {
        VALGRIND_MAKE_MEM_DEFINED(buffer, length);
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), GET, SHORT, length);
    ucs_trace_data("GET_SHORT [ptr %p len %u] from 0x%" PRIx64, buffer,
                   length, remote_addr);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_copy_ep_get_zcopy,
                 (tl_ep, iov, iovcnt, remote_addr, rkey, comp),
                 uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                 uint64_t remote_addr, uct_rkey_t rkey,
                 uct_completion_t *comp)
{
    ucs_status_t status;


    status = uct_gaudi_copy_post_gaudi_async_copy(tl_ep, iov[0].buffer,
                                                (void *)remote_addr,
                                                iov[0].length, comp);
    if (!UCS_STATUS_IS_ERR(status)) {
        VALGRIND_MAKE_MEM_DEFINED(iov[0].buffer, iov[0].length);
    }

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), GET, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    uct_gaudi_copy_trace_data("GET_ZCOPY", remote_addr, iov, iovcnt);
    return status;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_copy_ep_put_zcopy,
                 (tl_ep, iov, iovcnt, remote_addr, rkey, comp),
                 uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                 uint64_t remote_addr, uct_rkey_t rkey,
                 uct_completion_t *comp)
{

    ucs_status_t status;

    status = uct_gaudi_copy_post_gaudi_async_copy(tl_ep, (void *)remote_addr,
                                                iov[0].buffer,
                                                iov[0].length, comp);

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), PUT, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    uct_gaudi_copy_trace_data("PUT_ZCOPY", remote_addr, iov, iovcnt);
    return status;

}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_copy_ep_put_short,
                 (tl_ep, buffer, length, remote_addr, rkey),
                 uct_ep_h tl_ep, const void *buffer, unsigned length,
                 uint64_t remote_addr, uct_rkey_t rkey)
{
    ucs_status_t status;

    status = uct_gaudi_copy_post_gaudi_async_copy(tl_ep, (void *)remote_addr,
                                                (void *)buffer,
                                                length, NULL);

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), PUT, SHORT,
                      length);
    ucs_trace_data("PUT_SHORT [ptr %p len %u] to 0x%" PRIx64, buffer,
                   length, remote_addr);
    return status;
}