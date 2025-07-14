
/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudi_copy_md.h"
#include "../base/gaudi_md.h"

#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/memory/memtype_cache.h>
#include <ucs/profile/profile.h>
#include <ucs/type/class.h>
#include <ucs/sys/math.h>
#include <uct/api/v2/uct_v2.h>
#include <uct/gaudi/base/gaudi_iface.h>
#include <ucm/api/ucm.h>

/* Habana Labs driver */
#include <hlthunk.h>
#include <drm/habanalabs_accel.h>

#include <cjson/cJSON.h>

#define HLTHUNK_BUS_ID_MAX_LEN 32


static ucs_config_field_t uct_gaudi_copy_md_config_table[] = {
    {"", "", NULL,
        ucs_offsetof(uct_gaudi_copy_md_config_t, super), UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},

    {"REG_WHOLE_ALLOC", "auto",
     "Allow registration of whole allocation\n"
     " auto - Let runtime decide where whole allocation registration is turned on.\n"
     "        By default this will be turned off for limited BAR GPUs (eg. T4)\n"
     " on   - Whole allocation registration is always turned on.\n"
     " off  - Whole allocation registration is always turned off.",
     ucs_offsetof(uct_gaudi_copy_md_config_t, alloc_whole_reg),
     UCS_CONFIG_TYPE_ON_OFF_AUTO},

    {"MAX_REG_RATIO", "0.1",
     "If the ratio of the length of the allocation to which the user buffer belongs to"
     " to the total GPU memory capacity is below this ratio, then the whole allocation"
     " is registered. Otherwise only the user specified region is registered.",
     ucs_offsetof(uct_gaudi_copy_md_config_t, max_reg_ratio), UCS_CONFIG_TYPE_DOUBLE},

    {"DMABUF", "try",
     "Enable using cross-device dmabuf file descriptor",
     ucs_offsetof(uct_gaudi_copy_md_config_t, enable_dmabuf),
                  UCS_CONFIG_TYPE_TERNARY},

    {"ENABLE_RCACHE", "try", 
     "Enable registration cache for improved performance",
     ucs_offsetof(uct_gaudi_copy_md_config_t, enable_rcache),
     UCS_CONFIG_TYPE_TERNARY_AUTO},

    {"RCACHE_", "", NULL,
     ucs_offsetof(uct_gaudi_copy_md_config_t, rcache),
     UCS_CONFIG_TYPE_TABLE(ucs_config_rcache_table)},

    {"REG_COST", "7000ns",
     "Memory registration cost estimation",
     ucs_offsetof(uct_gaudi_copy_md_config_t, reg_cost),
     UCS_CONFIG_TYPE_TIME},

    {"ENABLE_MAPPED_DMABUF", "try",
     "Enable enhanced DMA-BUF support with offset capability (Gaudi2+)",
     ucs_offsetof(uct_gaudi_copy_md_config_t, enable_mapped_dmabuf),
     UCS_CONFIG_TYPE_TERNARY_AUTO},

    {"ENABLE_HW_BLOCK_ACCESS", "try",
     "Enable direct hardware block access for advanced features",
     ucs_offsetof(uct_gaudi_copy_md_config_t, enable_hw_block_access),
     UCS_CONFIG_TYPE_TERNARY_AUTO},

    {"ENABLE_NIC_SCALE_OUT", "try", 
     "Enable NIC-based scale-out communication capabilities",
     ucs_offsetof(uct_gaudi_copy_md_config_t, enable_nic_scale_out),
     UCS_CONFIG_TYPE_TERNARY_AUTO},

    {NULL}
};

/* Forward declarations */
static ucs_status_t uct_gaudi_copy_md_mem_query(uct_md_h uct_md, const void *address,
                                               size_t length,
                                               uct_md_mem_attr_t *mem_attr_p);

/* Check if Gaudi device is available for operations */

/* Forward declaration */
static int uct_gaudi_open_hlthunk_device(int device_index, ucs_sys_bus_id_t bus_id);

/* Ensure device is opened lazily when first needed */
static int uct_gaudi_copy_md_ensure_device_open(uct_gaudi_copy_md_t *md)
{
    ucs_sys_bus_id_t bus_id;
    char bus_id_str[64];
    
    if (md->hlthunk_fd >= 0) {
        return 1;  /* Already opened */
    }
    
    /* First time access - try to open device */
    bus_id = uct_gaudi_get_busid_from_env(md->device_index, bus_id_str);
    md->hlthunk_fd = uct_gaudi_open_hlthunk_device(md->device_index, bus_id);
    
    if (md->hlthunk_fd < 0) {
        ucs_debug("Gaudi device %d unavailable (hlthunk_open failed)", md->device_index);
        return 0;  /* Device unavailable */
    }
    
    /* Get hardware information now that device is open */
    if (hlthunk_get_hw_ip_info(md->hlthunk_fd, &md->hw_info) != 0) {
        ucs_warn("Failed to get hardware info from hlthunk for device %d", md->device_index);
        memset(&md->hw_info, 0, sizeof(md->hw_info));
    }
    
    /* Update capabilities based on successful device opening */
    md->config.mapped_dmabuf_supported = 0;
    md->config.nic_ports_available = 0;
    
    /* Detect enhanced DMA-BUF support (Gaudi2+ feature) */
    if (md->hw_info.device_id >= HLTHUNK_DEVICE_GAUDI2) {
        /* Test if enhanced DMA-BUF API is available */
        int test_fd;
        ucs_warn("Testing enhanced DMA-BUF support on device %d", md->device_index);
        test_fd = hlthunk_device_mapped_memory_export_dmabuf_fd(
            md->hlthunk_fd, 0, 0, 0, 0);
        if (test_fd >= 0) {
            close(test_fd);
            md->config.mapped_dmabuf_supported = 1;
            ucs_debug("Enhanced DMA-BUF with offset support detected on device %d", md->device_index);
        } else if (test_fd != -ENOSYS) {
            md->config.mapped_dmabuf_supported = 1;
            ucs_debug("Enhanced DMA-BUF API available on device %d (test failed as expected)", md->device_index);
        }
    }
    
    /* Detect NIC ports for scale-out capabilities */
    if (md->hw_info.nic_ports_mask != 0) {
        md->config.nic_ports_available = __builtin_popcountll(md->hw_info.nic_ports_mask);
        ucs_debug("Detected %d NIC ports for scale-out: mask=0x%lx on device %d", 
                 md->config.nic_ports_available, md->hw_info.nic_ports_mask, md->device_index);
    }
    
    ucs_debug("Successfully opened Gaudi device %d on first access", md->device_index);
    return 1;  /* Device now available */
}

static inline int uct_gaudi_copy_md_is_device_active(uct_gaudi_copy_md_t *md)
{
    return uct_gaudi_copy_md_ensure_device_open(md);
}

static uct_gaudi_mem_t* 
uct_gaudi_copy_find_memh_by_address(uct_gaudi_copy_md_t *md, 
                                   const void *address, size_t length);

/* Dummy memh for already registered memory or unavailable device */
static struct {} uct_gaudi_dummy_memh;

#ifdef ENABLE_STATS
/* Statistics class definition */
static ucs_stats_class_t uct_gaudi_copy_md_stats_class = {
    .name           = "gaudi_copy_md",
    .num_counters   = UCT_GAUDI_COPY_STAT_LAST,
    .class_id       = UCS_STATS_CLASS_ID_INVALID,
    .counter_names  = {
        [UCT_GAUDI_COPY_STAT_REG_CACHE_HITS]    = "reg_cache_hits",
        [UCT_GAUDI_COPY_STAT_REG_CACHE_MISSES]  = "reg_cache_misses",
        [UCT_GAUDI_COPY_STAT_DMABUF_EXPORTS]    = "dmabuf_exports",
        [UCT_GAUDI_COPY_STAT_DMA_ERRORS]        = "dma_errors"
    }
};
#endif

/**
 * @brief Enhanced error handling - convert error code to string
 */
const char* uct_gaudi_error_string(int error_code)
{
    switch (error_code) {
        case UCT_GAUDI_ERR_DEVICE_NOT_FOUND:    return "Gaudi device not found";
        case UCT_GAUDI_ERR_OUT_OF_MEMORY:       return "Out of device memory";
        case UCT_GAUDI_ERR_INVALID_PARAMS:      return "Invalid parameters";
        case UCT_GAUDI_ERR_DEVICE_BUSY:         return "Device is busy";
        case UCT_GAUDI_ERR_DMA_FAILED:          return "DMA operation failed";
        case UCT_GAUDI_ERR_TIMEOUT:             return "Operation timed out";
        case UCT_GAUDI_ERR_PERMISSION_DENIED:   return "Permission denied";
        case UCT_GAUDI_ERR_CHANNEL_FAILED:      return "Channel operation failed";
        default:                                return "Unknown Gaudi error";
    }
}

/**
 * @brief Translate hlthunk error codes to UCX status codes
 */
ucs_status_t uct_gaudi_translate_error(int hlthunk_error)
{
    if (hlthunk_error == 0) {
        return UCS_OK;
    }
    
    switch (hlthunk_error) {
        case -ENODEV:
        case -ENOENT:
            return UCS_ERR_NO_DEVICE;
        case -ENOMEM:
            return UCS_ERR_NO_MEMORY;
        case -EINVAL:
            return UCS_ERR_INVALID_PARAM;
        case -EBUSY:
            return UCS_ERR_BUSY;
        case -ETIMEDOUT:
            return UCS_ERR_TIMED_OUT;
        case -EACCES:
        case -EPERM:
            return UCS_ERR_REJECTED;
        default:
            return UCS_ERR_IO_ERROR;
    }
}

/* Enhanced error logging macro */
#define UCT_GAUDI_FUNC_LOG(_func, _log_level, _error) \
    ucs_log((_log_level), "%s(%s:%d) failed: %s (error=%d)", \
            UCS_PP_MAKE_STRING(_func), ucs_basename(__FILE__), __LINE__, \
            uct_gaudi_error_string(_error), (_error))

/* UCT_GAUDI_FUNC is defined in gaudi_iface.h */

/**
 * @brief Check if a memory handle has DMA-BUF that can be shared with InfiniBand
 */
static int uct_gaudi_copy_has_dmabuf_for_ib(uct_mem_h memh)
{
    uct_gaudi_mem_t *gaudi_memh;
    
    if (memh == &uct_gaudi_dummy_memh) {
        return 0; /* Device memory doesn't have DMA-BUF */
    }
    
    gaudi_memh = (uct_gaudi_mem_t *)memh;
    return (gaudi_memh->dmabuf_fd >= 0);
}

/**
 * @brief Get DMA-BUF file descriptor for InfiniBand integration
 */
static int uct_gaudi_copy_get_dmabuf_fd(uct_mem_h memh)
{
    uct_gaudi_mem_t *gaudi_memh;
    
    if (memh == &uct_gaudi_dummy_memh) {
        return -1;
    }
    
    gaudi_memh = (uct_gaudi_mem_t *)memh;
    return gaudi_memh->dmabuf_fd;
}

/**
 * @brief Find memory handle by address range
 */
static uct_gaudi_mem_t* 
uct_gaudi_copy_find_memh_by_address(uct_gaudi_copy_md_t *md, 
                                   const void *address, size_t length)
{
    uct_gaudi_mem_t *gaudi_memh;
    uintptr_t addr_start = (uintptr_t)address;
    uintptr_t addr_end = addr_start + length;
    
    ucs_recursive_spin_lock(&md->memh_lock);
    ucs_list_for_each(gaudi_memh, &md->memh_list, list) {
        uintptr_t memh_start = (uintptr_t)gaudi_memh->vaddr;
        uintptr_t memh_end = memh_start + gaudi_memh->size;
        
        /* Check if the queried address range overlaps with this memory handle */
        if (addr_start >= memh_start && addr_end <= memh_end) {
            ucs_recursive_spin_unlock(&md->memh_lock);
            return gaudi_memh;
        }
    }
    ucs_recursive_spin_unlock(&md->memh_lock);
    
    return NULL;
}

ucs_status_t uct_gaudi_copy_md_query(uct_md_h md, uct_md_attr_v2_t *md_attr)
{
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    
    ucs_info("Gaudi MD query called - UCS_MEMORY_TYPE_HOST=%d, UCS_MEMORY_TYPE_GAUDI=%d", 
             UCS_MEMORY_TYPE_HOST, UCS_MEMORY_TYPE_GAUDI);
    
    md_attr->flags = UCT_MD_FLAG_REG | 
                    UCT_MD_FLAG_ALLOC |
                    UCT_MD_FLAG_NEED_RKEY;
                    
    if (gaudi_md->config.dmabuf_supported) {
        md_attr->flags |= UCT_MD_FLAG_REG_DMABUF;
    }
    
    md_attr->reg_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST) |
                            UCS_BIT(UCS_MEMORY_TYPE_GAUDI); /* Gaudi device memory */
    md_attr->reg_nonblock_mem_types = 0;
    md_attr->alloc_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST) |
                              UCS_BIT(UCS_MEMORY_TYPE_GAUDI);
    md_attr->access_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST) |
                               UCS_BIT(UCS_MEMORY_TYPE_GAUDI);
    md_attr->detect_mem_types = UCS_BIT(UCS_MEMORY_TYPE_GAUDI);
    md_attr->dmabuf_mem_types = gaudi_md->config.dmabuf_supported ? 
                               UCS_BIT(UCS_MEMORY_TYPE_GAUDI) : 0;
    md_attr->max_alloc = UINT64_MAX;
    md_attr->max_reg = UINT64_MAX;
    md_attr->rkey_packed_size = sizeof(uct_gaudi_key_t);
    
    memset(&md_attr->local_cpus, 0xff, sizeof(md_attr->local_cpus));
    
    ucs_info("Gaudi MD query result: reg_mem_types=0x%lx, alloc_mem_types=0x%lx", 
             md_attr->reg_mem_types, md_attr->alloc_mem_types);
    
    return UCS_OK;
}

ucs_status_t
uct_gaudi_copy_mkey_pack(uct_md_h md, uct_mem_h memh, void *address,
                        size_t length, const uct_md_mkey_pack_params_t *params,
                        void *mkey_buffer)
{
    uct_gaudi_key_t *packed_key = (uct_gaudi_key_t *)mkey_buffer;
    
    if (memh == &uct_gaudi_dummy_memh) {
        /* For device memory, pack device address info */
        packed_key->vaddr = (uint64_t)address;
        packed_key->length = length;
        packed_key->dmabuf_fd = -1; /* No DMA-BUF for device memory */
    } else {
        /* For registered/allocated memory, include DMA-BUF info for IB sharing */
        packed_key->vaddr = (uint64_t)address;
        packed_key->length = length;
        packed_key->dmabuf_fd = uct_gaudi_copy_get_dmabuf_fd(memh);
        
        if (uct_gaudi_copy_has_dmabuf_for_ib(memh)) {
            ucs_debug("Packing memory key with DMA-BUF fd=%d for IB transport", 
                      packed_key->dmabuf_fd);
        }
    }
    
    return UCS_OK;
}

ucs_status_t uct_gaudi_copy_mem_alloc(uct_md_h md, size_t *length_p,
                                     void **address_p, ucs_memory_type_t mem_type,
                                     ucs_sys_device_t sys_dev, unsigned flags, 
                                     const char *alloc_name, uct_mem_h *memh_p)
{
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    uct_gaudi_mem_t *gaudi_memh;
    uint64_t handle;
    uint64_t addr;

    if (mem_type != UCS_MEMORY_TYPE_GAUDI) {
        ucs_error("Invalid memory type %d for Gaudi copy MD", mem_type);
        return UCS_ERR_UNSUPPORTED;
    }
    
    /* Check if Gaudi device is available */
    if (!uct_gaudi_copy_md_is_device_active(gaudi_md)) {
        ucs_debug("Gaudi device unavailable for memory allocation");
        return UCS_ERR_NO_DEVICE;
    }
    
    ucs_debug("uct_gaudi_copy_mem_alloc called: length=%zu, mem_type=%d, flags=0x%x", 
              *length_p, mem_type, flags);
    
    /* Allocate device memory through hl-thunk */
    handle = hlthunk_device_memory_alloc(gaudi_md->hlthunk_fd, *length_p, 
                                      0, true, true);
    if (handle == 0) {
        ucs_debug("Failed to allocate device memory size %zu", *length_p);
        UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMA_ERRORS, 1);
        return UCS_ERR_NO_MEMORY;
    }
    
    ucs_debug("Successfully allocated device memory handle 0x%lx", handle);
    
    /* Map to host address space */
    addr = hlthunk_device_memory_map(gaudi_md->hlthunk_fd, handle, 0);
    if (addr == 0) {
        hlthunk_device_memory_free(gaudi_md->hlthunk_fd, handle);
        ucs_error("Failed to map device memory handle 0x%lx", handle);
        UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMA_ERRORS, 1);
        return UCS_ERR_NO_MEMORY;
    }
    
    ucs_debug("Successfully mapped device memory to host address 0x%lx", addr);
    
    gaudi_memh = ucs_calloc(1, sizeof(*gaudi_memh), "gaudi_memh");
    if (gaudi_memh == NULL) {
        hlthunk_device_memory_free(gaudi_md->hlthunk_fd, handle);
        ucs_error("Failed to allocate Gaudi memory handle on host");
        return UCS_ERR_NO_MEMORY;
    }

    gaudi_memh->vaddr = (void *)addr; 
    gaudi_memh->size = *length_p;
    gaudi_memh->handle = handle;
    gaudi_memh->dev_addr = addr;
    gaudi_memh->dmabuf_fd = -1;
    gaudi_memh->dmabuf_offset = 0;
    gaudi_memh->is_mapped_memory = 1;
    
    /* Add to tracking list */
    ucs_recursive_spin_lock(&gaudi_md->memh_lock);
    ucs_list_add_tail(&gaudi_md->memh_list, &gaudi_memh->list);
    ucs_recursive_spin_unlock(&gaudi_md->memh_lock);
    
    ucs_trace("Allocated Gaudi memory handle %p, size %zu, dev addr 0x%lx",
              gaudi_memh, *length_p, gaudi_memh->dev_addr);

    /* Optionally export as DMA-BUF if flags indicate it */
    if (flags & UCT_MD_MEM_FLAG_FIXED) {
        int dmabuf_fd = -1;
        
        /* Try enhanced DMA-BUF API first (Gaudi2+) */
        if (gaudi_md->config.mapped_dmabuf_supported) {
            ucs_warn("Exporting memory as enhanced DMA-BUF fd for IB sharing");
            dmabuf_fd = hlthunk_device_mapped_memory_export_dmabuf_fd(
                gaudi_md->hlthunk_fd, (uint64_t)addr, *length_p, 0, 0);
            if (dmabuf_fd >= 0) {
                gaudi_memh->dmabuf_offset = 0;
                ucs_debug("Exported as enhanced DMA-BUF fd %d with offset support", dmabuf_fd);
            }
        }
        
        /* Fallback to legacy DMA-BUF API */
        if (dmabuf_fd < 0) {
            dmabuf_fd = hlthunk_device_memory_export_dmabuf_fd(gaudi_md->hlthunk_fd, 
                                                             (uint64_t)addr, *length_p, 0);
        }
        
        if (dmabuf_fd >= 0) {
            gaudi_memh->dmabuf_fd = dmabuf_fd;
            UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMABUF_EXPORTS, 1);
            ucs_debug("Exported allocated memory as DMA-BUF fd %d for IB sharing", dmabuf_fd);
        } else {
            ucs_warn("Failed to export allocated memory as DMA-BUF (fd=%d)", dmabuf_fd);
            UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMA_ERRORS, 1);
        }
    }

    *address_p = (void *)addr;
    *memh_p = gaudi_memh;
    
    return UCS_OK;
}

ucs_status_t uct_gaudi_copy_mem_free(uct_md_h md, uct_mem_h memh)
{
    uct_gaudi_mem_t *gaudi_memh = memh;
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    
    /* Handle dummy memory handle for unavailable devices */
    if (memh == &uct_gaudi_dummy_memh) {
        ucs_debug("Freeing dummy memory handle for unavailable device");
        return UCS_OK;
    }
    
    /* Remove from tracking list */
    ucs_recursive_spin_lock(&gaudi_md->memh_lock);
    ucs_list_del(&gaudi_memh->list);
    ucs_recursive_spin_unlock(&gaudi_md->memh_lock);
    
    /* Close DMA-BUF file descriptor if it was created */
    if (gaudi_memh->dmabuf_fd >= 0) {
        close(gaudi_memh->dmabuf_fd);
        ucs_debug("Closed DMA-BUF fd %d during memory free", 
                  gaudi_memh->dmabuf_fd);
    }
    
    if (gaudi_md->hlthunk_fd >= 0 && gaudi_memh->handle != 0) {
        hlthunk_device_memory_free(gaudi_md->hlthunk_fd, gaudi_memh->handle);
    }
    
    ucs_free(gaudi_memh);
    return UCS_OK;
}

static ucs_status_t
uct_gaudi_copy_md_query_attributes(const uct_gaudi_copy_md_t *md,
                                  const void *address, size_t length,
                                  ucs_memory_info_t *mem_info)
{
    struct hl_info_args args = {0};
    struct hl_info_hw_ip_info hw_ip;

    args.op = HL_INFO_HW_IP_INFO;
    args.return_pointer = (uintptr_t)&hw_ip;
    args.return_size = sizeof(hw_ip);

    /* Use the device index from the MD instead of hard-coding 0 */
    if (hlthunk_get_info(md->hlthunk_fd, &args)) {
        return UCS_ERR_INVALID_ADDR;
    }

    mem_info->type         = UCS_MEMORY_TYPE_GAUDI;
    mem_info->sys_dev      = md->device_index;
    mem_info->base_address = (void*)hw_ip.dram_base_address;
    mem_info->alloc_length = hw_ip.dram_size;

    return UCS_OK;
}

ucs_status_t
uct_gaudi_copy_md_mem_query(uct_md_h tl_md, const void *address, size_t length,
                           uct_md_mem_attr_t *mem_attr)
{
    ucs_memory_info_t default_mem_info = {
        .type         = UCS_MEMORY_TYPE_HOST,
        .sys_dev      = UCS_SYS_DEVICE_ID_UNKNOWN,
        .base_address = (void*)address,
        .alloc_length = length
    };
    uct_gaudi_copy_md_t *md = ucs_derived_of(tl_md, uct_gaudi_copy_md_t);
    ucs_memory_info_t addr_mem_info;
    ucs_status_t status;

    if (!(mem_attr->field_mask &
          (UCT_MD_MEM_ATTR_FIELD_MEM_TYPE | UCT_MD_MEM_ATTR_FIELD_SYS_DEV |
           UCT_MD_MEM_ATTR_FIELD_BASE_ADDRESS |
           UCT_MD_MEM_ATTR_FIELD_ALLOC_LENGTH |
           UCT_MD_MEM_ATTR_FIELD_DMABUF_FD |
           UCT_MD_MEM_ATTR_FIELD_DMABUF_OFFSET))) {
        return UCS_OK;
    }

    if (address != NULL) {
        status = uct_gaudi_copy_md_query_attributes(md, address, length,
                                                   &addr_mem_info);
        if (status != UCS_OK) {
            return status;
        }

        ucs_memtype_cache_update(addr_mem_info.base_address,
                                 addr_mem_info.alloc_length, addr_mem_info.type,
                                 addr_mem_info.sys_dev);
    } else {
        addr_mem_info = default_mem_info;
    }

    if (mem_attr->field_mask & UCT_MD_MEM_ATTR_FIELD_MEM_TYPE) {
        mem_attr->mem_type = addr_mem_info.type;
    }

    if (mem_attr->field_mask & UCT_MD_MEM_ATTR_FIELD_SYS_DEV) {
        mem_attr->sys_dev = addr_mem_info.sys_dev;
    }

    if (mem_attr->field_mask & UCT_MD_MEM_ATTR_FIELD_BASE_ADDRESS) {
        mem_attr->base_address = addr_mem_info.base_address;
    }

    if (mem_attr->field_mask & UCT_MD_MEM_ATTR_FIELD_ALLOC_LENGTH) {
        mem_attr->alloc_length = addr_mem_info.alloc_length;
    }

    if (mem_attr->field_mask & UCT_MD_MEM_ATTR_FIELD_DMABUF_FD) {
        /* Try to find if this memory region was allocated/registered with DMA-BUF support */
        uct_gaudi_mem_t *memh = uct_gaudi_copy_find_memh_by_address(md, address, length);
        if (memh && memh->dmabuf_fd >= 0) {
            mem_attr->dmabuf_fd = memh->dmabuf_fd;
        } else {
            /* No cached DMA-BUF FD found, try to export memory on-demand */
            int export_fd;
            ucs_warn("No cached DMA-BUF FD found for address %p, exporting on-demand", address);
            export_fd = hlthunk_device_memory_export_dmabuf_fd(md->hlthunk_fd, 
                                                                  (uint64_t)address, length, 0);
            if (export_fd >= 0) {
                mem_attr->dmabuf_fd = export_fd;
                ucs_debug("On-demand DMA-BUF export successful: fd=%d for addr=%p size=%zu", 
                         export_fd, address, length);
            } else {
                mem_attr->dmabuf_fd = UCT_DMABUF_FD_INVALID;
                ucs_debug("On-demand DMA-BUF export failed for addr=%p size=%zu", 
                         address, length);
            }
        }
    }

    if (mem_attr->field_mask & UCT_MD_MEM_ATTR_FIELD_DMABUF_OFFSET) {
        /* For now, Gaudi DMA-BUF exports start at offset 0 */
        mem_attr->dmabuf_offset = 0; 
    }

    return UCS_OK;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_copy_md_detect_memory_type,
                 (md, address, length, mem_type_p), uct_md_h md,
                 const void *address, size_t length,
                 ucs_memory_type_t *mem_type_p)
{
    uct_md_mem_attr_t mem_attr;
    ucs_status_t status;

    mem_attr.field_mask = UCT_MD_MEM_ATTR_FIELD_MEM_TYPE;

    status = uct_gaudi_copy_md_mem_query(md, address, length, &mem_attr);
    if (status != UCS_OK) {
        return status;
    }

    *mem_type_p = mem_attr.mem_type;
    return UCS_OK;
}

#if 0  /* Registration cache operations - disabled for now */
static ucs_status_t uct_gaudi_rcache_mem_reg_cb(void *context, ucs_rcache_t *rcache,
                                               void *arg, ucs_rcache_region_t *rregion,
                                               uint16_t rcache_mem_reg_flags)
{
    uct_gaudi_copy_md_t *md = (uct_gaudi_copy_md_t*)context;
    uct_gaudi_copy_rcache_region_t *region = ucs_derived_of(rregion, uct_gaudi_copy_rcache_region_t);
    uct_md_mem_reg_params_t *params = (uct_md_mem_reg_params_t*)arg;
    ucs_status_t status;
    
    status = uct_gaudi_copy_mem_reg(&md->super, (void*)region->super.super.start,
                                   region->super.super.end - region->super.super.start,
                                   params, (uct_mem_h*)&region->memh);
    if (status == UCS_OK) {
        UCS_STATS_UPDATE_COUNTER(md->stats, UCT_GAUDI_COPY_STAT_REG_CACHE_MISSES, 1);
    }
    
    return status;
}

static void uct_gaudi_rcache_mem_dereg_cb(void *context, ucs_rcache_t *rcache,
                                         ucs_rcache_region_t *rregion)
{
    uct_gaudi_copy_md_t *md = (uct_gaudi_copy_md_t*)context;
    uct_gaudi_copy_rcache_region_t *region = ucs_derived_of(rregion, uct_gaudi_copy_rcache_region_t);
    uct_md_mem_dereg_params_t params = {
        .field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH,
        .memh = (uct_mem_h)&region->memh
    };
    
    uct_gaudi_copy_mem_dereg(&md->super, &params);
}

static void uct_gaudi_copy_rcache_dump_region(void *context, ucs_rcache_t *rcache,
                                             ucs_rcache_region_t *rregion, char *buf, size_t max)
{
    uct_gaudi_copy_rcache_region_t *region = ucs_derived_of(rregion, uct_gaudi_copy_rcache_region_t);
    snprintf(buf, max, "bar ptr:%p handle:0x%lx", region->memh.vaddr, region->memh.handle);
}
#endif

#if 0  /* Disabled for now */
static ucs_rcache_ops_t uct_gaudi_copy_rcache_ops = {
    .mem_reg     = uct_gaudi_rcache_mem_reg_cb,
    .mem_dereg   = uct_gaudi_rcache_mem_dereg_cb,
    .dump_region = uct_gaudi_copy_rcache_dump_region
};
#endif

/* Enhanced registration functions that use cache when available */
ucs_status_t uct_gaudi_copy_rcache_mem_reg(uct_md_h md, void *address, size_t length,
                                          const uct_md_mem_reg_params_t *params, 
                                          uct_mem_h *memh_p)
{
    /* TODO: Implement rcache support */
    return uct_gaudi_copy_mem_reg(md, address, length, params, memh_p);
}

ucs_status_t uct_gaudi_copy_rcache_mem_dereg(uct_md_h md, 
                                            const uct_md_mem_dereg_params_t *params)
{
    /* TODO: Implement rcache support */
    return uct_gaudi_copy_mem_dereg(md, params);
}

/**
 * @brief Export device memory as DMA-BUF for device-to-device IPC
 * 
 * This function exports device memory as a DMA-BUF file descriptor that can be
 * shared with other Gaudi devices for zero-copy communication.
 */
ucs_status_t uct_gaudi_copy_export_dmabuf(uct_md_h md, void *address, size_t length,
                                         int *dmabuf_fd, uint64_t *dmabuf_offset)
{
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    int fd = -1;
    
    if (!address || !length || !dmabuf_fd) {
        return UCS_ERR_INVALID_PARAM;
    }
    
    *dmabuf_fd = -1;
    *dmabuf_offset = 0;
    
    /* Try enhanced DMA-BUF API first (Gaudi2+) */
    if (gaudi_md->config.mapped_dmabuf_supported) {
        ucs_warn("Exporting memory as enhanced DMA-BUF fd for device-to-device IPC");
        fd = hlthunk_device_mapped_memory_export_dmabuf_fd(
            gaudi_md->hlthunk_fd, (uint64_t)address, length, 0, 0);
        if (fd >= 0) {
            *dmabuf_fd = fd;
            *dmabuf_offset = 0;
            UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMABUF_EXPORTS, 1);
            ucs_debug("Exported enhanced DMA-BUF fd=%d for addr=%p size=%zu", 
                     fd, address, length);
            return UCS_OK;
        }
    }
    
    /* Fallback to legacy DMA-BUF API */
    fd = hlthunk_device_memory_export_dmabuf_fd(gaudi_md->hlthunk_fd, 
                                              (uint64_t)address, length, 0);
    if (fd >= 0) {
        *dmabuf_fd = fd;
        *dmabuf_offset = 0;
        UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMABUF_EXPORTS, 1);
        ucs_debug("Exported legacy DMA-BUF fd=%d for addr=%p size=%zu", 
                 fd, address, length);
        return UCS_OK;
    }
    
    ucs_error("Failed to export DMA-BUF for addr=%p size=%zu: %s", 
             address, length, strerror(errno));
    UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMA_ERRORS, 1);
    return UCS_ERR_IO_ERROR;
}

/**
 * @brief Import DMA-BUF from another device for device-to-device IPC
 * 
 * This function imports a DMA-BUF file descriptor from another Gaudi device
 * and maps it to a device virtual address for local access.
 */
ucs_status_t uct_gaudi_copy_import_dmabuf(uct_md_h md, int dmabuf_fd, size_t length,
                                         uint64_t offset, uint64_t *device_va)
{
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    union hl_mem_args ioctl_args;
    int rc;
    
    if (dmabuf_fd < 0 || !length || !device_va) {
        return UCS_ERR_INVALID_PARAM;
    }
    
    *device_va = 0;
    
    /* Register DMA-BUF with the device */
    memset(&ioctl_args, 0, sizeof(ioctl_args));
    ioctl_args.in.reg_dmabuf_fd.fd = dmabuf_fd;
    ioctl_args.in.reg_dmabuf_fd.length = length;
    ioctl_args.in.op = HL_MEM_OP_REG_DMABUF_FD;
    
    rc = ioctl(gaudi_md->hlthunk_fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
    if (rc) {
        ucs_error("Failed to register DMA-BUF fd=%d length=%zu: %s", 
                 dmabuf_fd, length, strerror(errno));
        UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMA_ERRORS, 1);
        return uct_gaudi_translate_error(rc);
    }
    
    *device_va = ioctl_args.out.device_virt_addr;
    
    ucs_debug("Imported DMA-BUF fd=%d length=%zu -> device_va=0x%lx", 
             dmabuf_fd, length, *device_va);
    
    return UCS_OK;
}

/**
 * @brief Unmap DMA-BUF device virtual address
 * 
 * This function unmaps a previously imported DMA-BUF from the device
 * virtual address space.
 */
ucs_status_t uct_gaudi_copy_unmap_dmabuf(uct_md_h md, uint64_t device_va)
{
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    union hl_mem_args ioctl_args;
    int rc;
    
    if (!device_va) {
        return UCS_ERR_INVALID_PARAM;
    }
    
    /* Unmap the device virtual address */
    memset(&ioctl_args, 0, sizeof(ioctl_args));
    ioctl_args.in.unmap.device_virt_addr = device_va;
    ioctl_args.in.op = HL_MEM_OP_UNMAP;
    
    rc = ioctl(gaudi_md->hlthunk_fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
    if (rc) {
        ucs_warn("Failed to unmap DMA-BUF device_va=0x%lx: %s", 
                device_va, strerror(errno));
        UCS_STATS_UPDATE_COUNTER(gaudi_md->stats, UCT_GAUDI_COPY_STAT_DMA_ERRORS, 1);
        return uct_gaudi_translate_error(rc);
    }
    
    ucs_debug("Unmapped DMA-BUF device_va=0x%lx", device_va);
    return UCS_OK;
}

static void uct_gaudi_copy_md_close(uct_md_h uct_md) {
    uct_gaudi_copy_md_t *md = ucs_derived_of(uct_md, uct_gaudi_copy_md_t);
    uct_gaudi_mem_t *gaudi_memh, *tmp;

    /* Clean up any remaining memory handles */
    ucs_recursive_spin_lock(&md->memh_lock);
    ucs_list_for_each_safe(gaudi_memh, tmp, &md->memh_list, list) {
        ucs_list_del(&gaudi_memh->list);
        ucs_warn("Cleaning up unreleased memory handle %p", gaudi_memh);
        if (gaudi_memh->dmabuf_fd >= 0) {
            close(gaudi_memh->dmabuf_fd);
        }
        if (gaudi_memh->handle != 0 && md->hlthunk_fd >= 0) {
            hlthunk_device_memory_free(md->hlthunk_fd, gaudi_memh->handle);
        }
        ucs_free(gaudi_memh);
    }
    ucs_recursive_spin_unlock(&md->memh_lock);
    
    ucs_recursive_spinlock_destroy(&md->memh_lock);

    /* Cleanup registration cache */
    if (md->rcache != NULL) {
        ucs_rcache_destroy(md->rcache);
    }

    /* Cleanup statistics */
#ifdef ENABLE_STATS
    UCS_STATS_NODE_FREE(md->stats);
#endif

    if (md->hlthunk_fd >= 0) {
        hlthunk_close(md->hlthunk_fd);
    }

    ucs_free(md);
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_copy_mem_reg,
                 (md, address, length, params, memh_p),
                 uct_md_h md, void *address, size_t length,
                 const uct_md_mem_reg_params_t *params, uct_mem_h *memh_p)
{
    uct_gaudi_copy_md_t *gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    uint64_t flags = UCT_MD_MEM_REG_FIELD_VALUE(params, flags, FIELD_FLAGS, 0);
    uct_gaudi_mem_t *gaudi_memh;
    
    /* Check if Gaudi device is available */
    if (!uct_gaudi_copy_md_is_device_active(gaudi_md)) {
        ucs_debug("Gaudi device unavailable for memory registration, returning dummy handle");
        *memh_p = &uct_gaudi_dummy_memh;
        return UCS_OK;
    }
    
    /* Check if this is already Gaudi device memory */
    if ((uintptr_t)address >= gaudi_md->hw_info.dram_base_address &&
        (uintptr_t)address < (gaudi_md->hw_info.dram_base_address + gaudi_md->hw_info.dram_size)) {
        /* Already device memory, just create a dummy handle */
        *memh_p = &uct_gaudi_dummy_memh;
        return UCS_OK;
    }
    
    /* Allocate memory handle */
    gaudi_memh = ucs_calloc(1, sizeof(*gaudi_memh), "gaudi_memh");
    if (gaudi_memh == NULL) {
        return UCS_ERR_NO_MEMORY;
    }
    
    /* Register the memory */
    gaudi_memh->vaddr = address;
    gaudi_memh->size = length;
    gaudi_memh->handle = 0;
    gaudi_memh->dev_addr = (uint64_t)address;
    gaudi_memh->dmabuf_fd = -1;
    
    /* Add to tracking list */
    ucs_recursive_spin_lock(&gaudi_md->memh_lock);
    ucs_list_add_tail(&gaudi_md->memh_list, &gaudi_memh->list);
    ucs_recursive_spin_unlock(&gaudi_md->memh_lock);
    
    /* Export as DMA-BUF if requested and supported */
    if ((flags & UCT_MD_MEM_FLAG_FIXED) && gaudi_md->config.dmabuf_supported) {
        int dmabuf_fd;
        /* Export host memory mapped to Gaudi as DMA-BUF for IB sharing */
        dmabuf_fd = hlthunk_device_mapped_memory_export_dmabuf_fd(gaudi_md->hlthunk_fd,
                                                                 (uint64_t)address, length, 0, 0);
        if (dmabuf_fd >= 0) {
            gaudi_memh->dmabuf_fd = dmabuf_fd;
            ucs_debug("Exported registered memory %p as DMA-BUF fd %d for IB sharing", 
                      address, dmabuf_fd);
        } else {
            ucs_debug("Failed to export registered memory as DMA-BUF (fd=%d)", dmabuf_fd);
        }
    }
    
    ucs_trace("Registered Gaudi memory %p, size %zu", address, length);
    
    *memh_p = gaudi_memh;
    return UCS_OK;
}

UCS_PROFILE_FUNC(ucs_status_t, uct_gaudi_copy_mem_dereg,
                 (md, params),
                 uct_md_h md, const uct_md_mem_dereg_params_t *params)
{
    uct_gaudi_mem_t *gaudi_memh;
    uct_gaudi_copy_md_t *gaudi_md;
    
    UCT_MD_MEM_DEREG_CHECK_PARAMS(params, 0);
    
    if (params->memh == &uct_gaudi_dummy_memh) {
        /* This was already device memory, nothing to do */
        return UCS_OK;
    }
    
    gaudi_memh = (uct_gaudi_mem_t *)params->memh;
    gaudi_md = ucs_derived_of(md, uct_gaudi_copy_md_t);
    
    /* Remove from tracking list */
    ucs_recursive_spin_lock(&gaudi_md->memh_lock);
    ucs_list_del(&gaudi_memh->list);
    ucs_recursive_spin_unlock(&gaudi_md->memh_lock);
    
    /* Close DMA-BUF file descriptor if it was created */
    if (gaudi_memh->dmabuf_fd >= 0) {
        close(gaudi_memh->dmabuf_fd);
    }
    
    /* Free any device memory handle if it was allocated */
    if (gaudi_memh->handle != 0) {
        if (gaudi_md->hlthunk_fd >= 0) {
            hlthunk_device_memory_free(gaudi_md->hlthunk_fd, gaudi_memh->handle);
        }
    }
    
    ucs_free(gaudi_memh);
    return UCS_OK;
}

static ucs_status_t
uct_gaudi_copy_mem_attach(uct_md_h md, const void *rkey_buffer, 
                          uct_md_mem_attach_params_t *params, uct_mem_h *memh_p)
{
    const uct_gaudi_key_t *gaudi_key = (const uct_gaudi_key_t *)rkey_buffer;
    uct_gaudi_mem_t *gaudi_memh;
    
    gaudi_memh = ucs_calloc(1, sizeof(*gaudi_memh), "gaudi_attach_memh");
    if (gaudi_memh == NULL) {
        return UCS_ERR_NO_MEMORY;
    }
    
    gaudi_memh->vaddr = (void *)gaudi_key->vaddr;
    gaudi_memh->size = gaudi_key->length;
    gaudi_memh->handle = 0; /* Remote handle not needed for attach */
    gaudi_memh->dev_addr = gaudi_key->vaddr;
    gaudi_memh->dmabuf_fd = gaudi_key->dmabuf_fd;
    
    /* Note: we don't import the DMA-BUF here, just store the fd */
    
    *memh_p = gaudi_memh;
    return UCS_OK;
}

static uct_md_ops_t md_ops = {
    .close              = uct_gaudi_copy_md_close,
    .query              = uct_gaudi_copy_md_query,
    .mem_alloc          = uct_gaudi_copy_mem_alloc,
    .mem_free           = uct_gaudi_copy_mem_free,
    .mem_advise         = (uct_md_mem_advise_func_t)ucs_empty_function_return_unsupported,
    .mem_reg            = uct_gaudi_copy_mem_reg,
    .mem_dereg          = uct_gaudi_copy_mem_dereg,
    .mem_query          = uct_gaudi_copy_md_mem_query,
    .mkey_pack          = uct_gaudi_copy_mkey_pack,
    .mem_attach         = uct_gaudi_copy_mem_attach,
    .detect_memory_type = uct_gaudi_copy_md_detect_memory_type
};


static int uct_gaudi_open_hlthunk_device(int device_index, ucs_sys_bus_id_t bus_id)
{
    char bus_id_str[64];
    int fd;
    
    if (bus_id.domain == -1 || bus_id.bus == -1 || bus_id.slot == -1 || bus_id.function == -1) {
        ucs_warn("Failed to get valid bus ID for Gaudi device %d from environment", device_index);
        return -1;
    }
    
    snprintf(bus_id_str, sizeof(bus_id_str), "%04x:%02x:%02x.%x", bus_id.domain, bus_id.bus, bus_id.slot, bus_id.function);
    fd = hlthunk_open(device_index, bus_id_str);
    if (fd < 0) {
        ucs_warn("Failed to open hlthunk device %d (bus_id=%s), Gaudi transport will be disabled", device_index, bus_id_str);
    }
    else {
        ucs_warn("Opened hlthunk device %d with bus ID %s", device_index, bus_id_str);
    }
    return fd;
}

static ucs_status_t
uct_gaudi_copy_md_open(uct_component_t *component, const char *md_name,
                      const uct_md_config_t *md_config, uct_md_h *md_p)
{
    uct_gaudi_copy_md_t *md;
    uct_gaudi_copy_md_config_t *config;
    int device_index = 0; /* Default to first device */
#ifdef ENABLE_STATS
    ucs_status_t status;
#endif
    
    config = ucs_derived_of(md_config, uct_gaudi_copy_md_config_t);
    
    // Parse device index from md_name, e.g. "gaudi:0"
    if (md_name != NULL) {
        const char *colon = strchr(md_name, ':');
        if (colon != NULL) {
            device_index = atoi(colon + 1);
        }
    }

    md = ucs_calloc(1, sizeof(uct_gaudi_copy_md_t), "uct_gaudi_copy_md_t");
    if (NULL == md) {
        ucs_error("failed to allocate memory for uct_gaudi_copy_md_t");
        return UCS_ERR_NO_MEMORY;
    }

    md->super.ops       = &md_ops;
    md->super.component = &uct_gaudi_copy_component;
    
    /* Initialize device index and hlthunk fd */
    md->device_index = device_index; /* Default to first device */
    md->hlthunk_fd = -1;
    
    /* Initialize memory handle tracking */
    ucs_list_head_init(&md->memh_list);
    ucs_recursive_spinlock_init(&md->memh_lock, 0);

    /* Initialize configuration */
    md->config.dmabuf_supported = (config->enable_dmabuf != UCS_NO);
    md->config.enable_rcache = config->enable_rcache;
    md->config.max_reg_ratio = config->max_reg_ratio;
    md->config.alloc_whole_reg = config->alloc_whole_reg;
    
    /* Initialize registration cost estimation */
    md->reg_cost = ucs_linear_func_make(config->reg_cost, 0);
    
    /* Device will be opened lazily on first access - no device opening during MD init */
    ucs_debug("Gaudi MD initialized for device %d - device will be opened on first access", md->device_index);
    
    /* Initialize hardware info as empty - will be populated on first device access */
    memset(&md->hw_info, 0, sizeof(md->hw_info));
    
    /* Initialize advanced capabilities - will be detected on first device access */
    md->config.mapped_dmabuf_supported = 0;
    md->config.nic_ports_available = 0;
    
    /* Enhanced DMA-BUF and NIC detection will happen on first device access */
    ucs_debug("Enhanced DMA-BUF and NIC capabilities will be detected on first device access");
    
    md->device_type = "GAUDI";

    /* Initialize statistics */
#ifdef ENABLE_STATS
    status = UCS_STATS_NODE_ALLOC(&md->stats, &uct_gaudi_copy_md_stats_class, 
                                  ucs_stats_get_root(), "-%p", md);
    if (status != UCS_OK) {
        ucs_warn("Failed to initialize statistics");
        /* Continue without statistics */
    }
#endif

    /* Initialize registration cache if enabled */
    md->rcache = NULL;
    /* TODO: Implement proper rcache support */
    ucs_debug("Registration cache disabled for now");

    *md_p = (uct_md_h)md;

    return UCS_OK;
}

uct_component_t uct_gaudi_copy_component = {
    .query_md_resources = uct_gaudi_base_query_md_resources,
    .md_open            = uct_gaudi_copy_md_open,
    .cm_open            = (uct_component_cm_open_func_t)ucs_empty_function_return_unsupported,
    .rkey_unpack        = uct_md_stub_rkey_unpack,
    .rkey_ptr           = (uct_component_rkey_ptr_func_t)ucs_empty_function_return_unsupported,
    .rkey_release       = (uct_component_rkey_release_func_t)ucs_empty_function_return_success,
    .rkey_compare       = uct_base_rkey_compare,
    .name               = "gaudi_copy",
    .md_config          = {
        .name           = "Gaudi-copy memory domain",
        .prefix         = "GAUDI_COPY_",
        .table          = uct_gaudi_copy_md_config_table,
        .size           = sizeof(uct_gaudi_copy_md_config_t),
    },
    .cm_config          = UCS_CONFIG_EMPTY_GLOBAL_LIST_ENTRY,
    .tl_list            = UCT_COMPONENT_TL_LIST_INITIALIZER(&uct_gaudi_copy_component),
    .flags              = 0,
    .md_vfs_init        = (uct_component_md_vfs_init_func_t)ucs_empty_function
};

UCT_COMPONENT_REGISTER(&uct_gaudi_copy_component);
