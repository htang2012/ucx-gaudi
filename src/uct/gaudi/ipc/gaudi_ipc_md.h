/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifndef UCT_GAUDI_IPC_MD_H
#define UCT_GAUDI_IPC_MD_H

#include <uct/base/uct_md.h>
#include <uct/gaudi/base/gaudi_md.h>
#include <uct/gaudi/base/gaudi_iface.h>
#include <ucs/datastruct/khash.h>
#include <ucs/type/spinlock.h>
#include <ucs/config/types.h>
#include <habanalabs/synapse_api.h>
#include <habanalabs/synapse_api_types.h>
#include <habanalabs/synapse_common_types.h>

/**
 * @file gaudi_ipc_md.h
 * 
 * @brief Gaudi IPC Memory Domain - Custom Channel Communication Model
 * 
 * This implementation provides Inter-Process Communication (IPC) for Gaudi 
 * accelerators using a custom channel-based approach for node-local communication.
 * 
 * Key Features:
 * - Custom communication channels between Gaudi devices within a single node
 * - High-performance device-to-device memory transfers
 * - Efficient caching of channel mappings
 * - Fallback to traditional IPC handles when needed
 * 
 * Architecture:
 * 1. Node Device Detection: Automatically discovers all Gaudi devices in the node
 * 2. Channel Creation: Establishes custom channels between device pairs
 * 3. Memory Registration: Associates memory regions with channels
 * 4. Direct Transfer: Uses channels for zero-copy memory operations
 * 
 * Channel Model:
 * - Each channel connects two Gaudi devices within the same node
 * - Channels are bidirectional and cached for reuse
 * - Channel IDs are unique identifiers for device-pair communication
 * - Uses hlthunk_ipc_channel_* APIs for custom RDMA verbs communication
 */


typedef struct uct_gaudi_ipc_md_handle {
    uint64_t handle;            /* Legacy handle for compatibility */
    uint32_t channel_id;        /* Custom channel ID for node-local communication */
    uint32_t src_device_id;     /* Source Gaudi device ID */
    uint32_t dst_device_id;     /* Destination Gaudi device ID */
} uct_gaudi_ipc_md_handle_t;

/**
 * @brief gaudi ipc MD descriptor
 */
typedef struct uct_gaudi_ipc_md {
    uct_md_t                 super;
    int                      device_count;      /* Number of Gaudi devices in node */
    synDeviceId             *deviceIds;       /* Synapse device IDs */

    uint64_t                *channel_map;       /* Channel mapping between devices */
    pthread_mutex_t          channel_lock;      /* Lock for channel operations */
    int                      primary_device_fd; /* Primary device for this MD */
} uct_gaudi_ipc_md_t;


/**
 * @brief gaudi ipc component extension
 */
typedef struct {
    uct_component_t             super;
    pthread_mutex_t             lock;
    uct_gaudi_ipc_md_t         *node_md;        /* Shared MD for node-local communication */
    uint32_t                    node_device_mask; /* Bitmask of available devices in node */
} uct_gaudi_ipc_component_t;

extern uct_gaudi_ipc_component_t uct_gaudi_ipc_component;

/**
 * @brief gaudi ipc domain configuration.
 */
typedef struct uct_gaudi_ipc_md_config {
    uct_md_config_t          super;
} uct_gaudi_ipc_md_config_t;


/**
 * @brief list of gaudi ipc regions registered for memh
 */
typedef struct {
    pid_t           pid;
    int             dev_num;
    uint32_t        channel_id;    /* Channel ID for this memory registration */
    ucs_list_link_t list;
} uct_gaudi_ipc_memh_t;


/**
 * @brief gaudi ipc region registered for exposure
 */
typedef struct {
    uct_gaudi_ipc_md_handle_t  ph;
    void*                     d_bptr;
    size_t                    b_len;
    ucs_list_link_t           link;
} uct_gaudi_ipc_lkey_t;


/**
 * @brief gaudi ipc remote key for put/get
 */
typedef struct {
    uct_gaudi_ipc_md_handle_t  ph;
    pid_t                     pid;
    void*                     d_bptr;
    size_t                    b_len;
    uint32_t                  src_device_id;   /* Source device in custom channel */
    uint32_t                  dst_device_id;   /* Destination device in custom channel */
    uint32_t                  channel_id;      /* Custom channel identifier */
} uct_gaudi_ipc_rkey_t;


typedef struct {
    uct_gaudi_ipc_rkey_t       super;
} uct_gaudi_ipc_unpacked_rkey_t;

/* Custom channel management functions */
ucs_status_t uct_gaudi_ipc_channel_create(uct_gaudi_ipc_md_t *md, 
                                          uint32_t src_device, uint32_t dst_device,
                                          uint32_t *channel_id);

ucs_status_t uct_gaudi_ipc_channel_destroy(uct_gaudi_ipc_md_t *md, 
                                           uint32_t channel_id);

ucs_status_t uct_gaudi_ipc_channel_copy(uct_gaudi_ipc_md_t *md,
                                        uint32_t channel_id,
                                        void *dst, void *src, size_t length);



/* Direct Gaudi-to-Gaudi communication stub functions */
ucs_status_t uct_gaudi_ipc_enable_scale_out(uct_gaudi_ipc_md_t *md,
                                           uint32_t local_device_id,
                                           uint32_t remote_device_id);

ucs_status_t uct_gaudi_ipc_setup_hls_connection(uct_gaudi_ipc_md_t *md,
                                               uint32_t peer_device_id,
                                               uint32_t *connection_id);

ucs_status_t uct_gaudi_ipc_direct_transfer(uct_gaudi_ipc_md_t *md,
                                          uint32_t connection_id,
                                          uint64_t src_device_addr,
                                          uint64_t dst_device_addr,
                                          size_t length);

ucs_status_t uct_gaudi_ipc_query_topology(uct_gaudi_ipc_md_t *md,
                                         uint32_t device_count,
                                         uint32_t *device_ids,
                                         uint32_t *topology_map);

ucs_status_t uct_gaudi_ipc_setup_collective_ring(uct_gaudi_ipc_md_t *md,
                                                uint32_t device_count,
                                                uint32_t *device_ids,
                                                uint32_t *ring_id);

#endif
