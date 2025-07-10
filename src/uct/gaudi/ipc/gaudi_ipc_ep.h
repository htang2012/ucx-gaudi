/**
* Copyright (c) 2024, Habana Labs Ltd. an Intel Company
*/

#ifndef UCT_GAUDI_IPC_EP_H
#define UCT_GAUDI_IPC_EP_H

#include <uct/api/uct.h>
#include <uct/base/uct_iface.h>
#include <ucs/type/class.h>


typedef struct uct_gaudi_ipc_ep {
    uct_base_ep_t        super;
    pid_t                remote_pid;
} uct_gaudi_ipc_ep_t;


UCS_CLASS_DECLARE_NEW_FUNC(uct_gaudi_ipc_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_gaudi_ipc_ep_t, uct_ep_t);

ucs_status_t uct_gaudi_ipc_ep_get_zcopy(uct_ep_h tl_ep,
                                       const uct_iov_t *iov, size_t iovcnt,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_gaudi_ipc_ep_put_zcopy(uct_ep_h tl_ep,
                                       const uct_iov_t *iov, size_t iovcnt,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

int uct_gaudi_ipc_ep_is_connected(const uct_ep_h tl_ep,
                                 const uct_ep_is_connected_params_t *params);

#endif
