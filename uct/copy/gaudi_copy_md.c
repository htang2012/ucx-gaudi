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
#include <fcntl.h>
#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/memory/memtype_cache.h>
#include <ucs/profile/profile.h>
#include <ucs/type/class.h>
#include <ucs/sys/math.h>
#include <uct/api/v2/uct_v2.h>
#include <uct/gaudi/base/gaudi_iface.h>

/* Habana Labs driver */
#include <hlthunk.h>


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

    {NULL}
};

/* Forward declarations */
static ucs_status_t uct_gaudi_copy_md_mem_query(uct_md_h uct_md, const void *address,
                                               size_t length,
                                               uct_md_mem_attr_t *mem_attr_p);

static uct_gaudi_mem_t* 
uct_gaudi_copy_find_memh_by_address(uct_gaudi_copy_md_t *md, 
                                   const void *address, size_t length);

/* Dummy memh for already registered memory */
static struct {} uct_gaudi_dummy_memh;

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
    
    ucs_debug("uct_gaudi_copy_mem_alloc called: length=%zu, mem_type=%d, flags=0x%x", 
              *length_p, mem_type, flags);
    
    /* Allocate device memory through hl-thunk */
    handle = hlthunk_device_memory_alloc(gaudi_md->hlthunk_fd, *length_p, 
                                      0, true, true);
    if (handle == 0) {
        ucs_debug("Failed to allocate device memory size %zu", *length_p);
        return UCS_ERR_NO_MEMORY;
    }
    
    ucs_debug("Successfully allocated device memory handle 0x%lx", handle);
    
    /* Map to host address space */
    addr = hlthunk_device_memory_map(gaudi_md->hlthunk_fd, handle, 0);
    if (addr == 0) {
        hlthunk_device_memory_free(gaudi_md->hlthunk_fd, handle);
        ucs_error("Failed to map device memory handle 0x%lx", handle);
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
    
    /* Add to tracking list */
    ucs_recursive_spin_lock(&gaudi_md->memh_lock);
    ucs_list_add_tail(&gaudi_md->memh_list, &gaudi_memh->list);
    ucs_recursive_spin_unlock(&gaudi_md->memh_lock);
    
    ucs_trace("Allocated Gaudi memory handle %p, size %zu, dev addr 0x%lx",
              gaudi_memh, *length_p, gaudi_memh->dev_addr);

    /* Optionally export as DMA-BUF if flags indicate it */
    if (flags & UCT_MD_MEM_FLAG_FIXED) {
        /* Export device memory as DMA-BUF for sharing with InfiniBand */
        int dmabuf_fd = hlthunk_device_memory_export_dmabuf_fd(gaudi_md->hlthunk_fd, 
                                                             (uint64_t)addr, *length_p, 0);
        if (dmabuf_fd >= 0) {
            gaudi_memh->dmabuf_fd = dmabuf_fd;
            ucs_debug("Exported allocated memory as DMA-BUF fd %d for IB sharing", dmabuf_fd);
        } else {
            ucs_warn("Failed to export allocated memory as DMA-BUF (fd=%d)", dmabuf_fd);
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
        if (memh && uct_gaudi_copy_has_dmabuf_for_ib(memh)) {
            mem_attr->dmabuf_fd = uct_gaudi_copy_get_dmabuf_fd(memh);
        } else {
            mem_attr->dmabuf_fd = -1; /* Set to invalid by default */
        }
    }

    if (mem_attr->field_mask & UCT_MD_MEM_ATTR_FIELD_DMABUF_OFFSET) {
        mem_attr->dmabuf_offset = 0; /* Offset within DMA-BUF */
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
    
    /* Check if this is already Gaudi device memory */
    if (gaudi_md->hlthunk_fd >= 0 &&
        (uintptr_t)address >= gaudi_md->hw_info.dram_base_address &&
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

static ucs_status_t
uct_gaudi_copy_md_open(uct_component_t *component, const char *md_name,
                      const uct_md_config_t *md_config, uct_md_h *md_p)
{
    uct_gaudi_copy_md_t *md;
    uct_gaudi_copy_md_config_t *config;
    
    config = ucs_derived_of(md_config, uct_gaudi_copy_md_config_t);

    md = ucs_calloc(1, sizeof(uct_gaudi_copy_md_t), "uct_gaudi_copy_md_t");
    if (NULL == md) {
        ucs_error("failed to allocate memory for uct_gaudi_copy_md_t");
        return UCS_ERR_NO_MEMORY;
    }

    md->super.ops       = &md_ops;
    md->super.component = &uct_gaudi_copy_component;
    
    /* Initialize device index and hlthunk fd */
    md->device_index = 0; /* Default to first device */
    md->hlthunk_fd = -1;
    
    /* Initialize memory handle tracking */
    ucs_list_head_init(&md->memh_list);
    ucs_recursive_spinlock_init(&md->memh_lock, 0);
    
    /* Initialize configuration */
    md->config.dmabuf_supported = (config->enable_dmabuf != UCS_NO);
    
    /* Open hlthunk device */
    md->hlthunk_fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, NULL);
    if (md->hlthunk_fd < 0) {
        ucs_warn("Failed to open hlthunk device, Gaudi transport will be disabled");
        ucs_recursive_spinlock_destroy(&md->memh_lock);
        ucs_free(md);
        return UCS_ERR_NO_DEVICE;
    }
    
    /* Use default device index for now */
    md->device_index = 0;
    ucs_debug("Using default Gaudi device index: %d", md->device_index);
    
    /* Get hardware information */
    if (hlthunk_get_hw_ip_info(md->hlthunk_fd, &md->hw_info) != 0) {
        ucs_warn("Failed to get hardware info from hlthunk");
        memset(&md->hw_info, 0, sizeof(md->hw_info));
    }
    
    md->device_type = "GAUDI";
    ucs_debug("Opened Gaudi device fd=%d, DRAM base=0x%lx size=%lu", 
              md->hlthunk_fd, md->hw_info.dram_base_address, md->hw_info.dram_size);

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
