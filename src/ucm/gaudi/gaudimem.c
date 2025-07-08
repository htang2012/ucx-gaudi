/*
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "gaudimem.h"

#include <ucm/event/event.h>
#include <ucm/util/log.h>
#include <ucm/util/reloc.h>
#include <ucm/util/replace.h>
#include <ucs/debug/assert.h>
#include <ucm/util/sys.h>
#include <ucs/sys/compiler.h>
#include <ucs/sys/preprocessor.h>
#include <ucs/memory/memory_type.h>

#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static void ucm_gaudi_dispatch_mem_alloc(void *ptr, size_t length, ucs_memory_type_t mem_type)
{
    ucm_event_t event;

    event.mem_type.address  = ptr;
    event.mem_type.size     = length;
    event.mem_type.mem_type = mem_type;
    ucm_event_dispatch(UCM_EVENT_MEM_TYPE_ALLOC, &event);
}

static void ucm_gaudi_dispatch_mem_free(void *ptr, size_t length, 
                                        ucs_memory_type_t mem_type,
                                        const char *func_name)
{
    ucm_event_t event;

    if (ptr == NULL) {
        return;
    }

    if (length == 0) {
        length = 1; /* set minimum length */
    }

    event.mem_type.address  = ptr;
    event.mem_type.size     = length;
    event.mem_type.mem_type = mem_type;
    ucm_event_dispatch(UCM_EVENT_MEM_TYPE_FREE, &event);
}

/* Create a body of Gaudi memory allocation replacement function */
#define UCM_GAUDI_ALLOC_FUNC(_name, _retval, _success, _size, _ptr_type, _ref, \
                             _args_fmt, ...) \
    _retval ucm_##_name(_ptr_type _ref ptr_arg, \
                        UCM_FUNC_DEFINE_ARGS(__VA_ARGS__)) \
    { \
        _ptr_type ptr; \
        _retval ret; \
        \
        ucm_event_enter(); \
        ret = ucm_orig_##_name(ptr_arg, UCM_FUNC_PASS_ARGS(__VA_ARGS__)); \
        if (ret == (_success)) { \
            ptr = _ref ptr_arg; \
            ucm_trace("%s(" _args_fmt ") allocated %p", __func__, \
                      UCM_FUNC_PASS_ARGS(__VA_ARGS__), (void*)ptr); \
            ucm_gaudi_dispatch_mem_alloc((void*)ptr, (_size), UCS_MEMORY_TYPE_HOST); \
        } \
        ucm_event_leave(); \
        return ret; \
    }

/* Create a body of Gaudi memory release replacement function */
#define UCM_GAUDI_FREE_FUNC(_name, _mem_type, _retval, _ptr_arg, _size, \
                            _args_fmt, ...) \
    _retval ucm_##_name(UCM_FUNC_DEFINE_ARGS(__VA_ARGS__)) \
    { \
        _retval ret; \
        \
        ucm_event_enter(); \
        ucm_trace("%s(" _args_fmt ")", __func__, \
                  UCM_FUNC_PASS_ARGS(__VA_ARGS__)); \
        ucm_gaudi_dispatch_mem_free((void*)(_ptr_arg), _size, _mem_type, #_name); \
        ret = ucm_orig_##_name(UCM_FUNC_PASS_ARGS(__VA_ARGS__)); \
        ucm_event_leave(); \
        return ret; \
    }

/* Forward declarations for replacement functions */
void* ucm_hlthunk_malloc(size_t size);
int ucm_hlthunk_free(void *ptr);
uint64_t ucm_hlthunk_device_memory_alloc(int fd, uint64_t size, uint64_t page_size, 
                                         bool contiguous, bool shared);
int ucm_hlthunk_device_memory_free(int fd, uint64_t handle, uint64_t size);
uint64_t ucm_hlthunk_device_memory_map(int fd, uint64_t handle, uint64_t hint_addr, uint64_t size);
int ucm_hlthunk_memory_unmap(int fd, uint64_t addr);
int ucm_hlthunk_host_memory_alloc(int fd, uint64_t size, uint64_t *device_addr);
int ucm_hlthunk_host_memory_free(int fd, uint64_t device_addr);

/* Define function replacement macros for hlthunk functions */
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_malloc, void*, NULL, size_t)
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_free, int, -1, void*)
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_device_memory_alloc, uint64_t, 0, 
                                  int, uint64_t, uint64_t, bool, bool)
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_device_memory_free, int, -1, 
                                  int, uint64_t, uint64_t)
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_device_memory_map, uint64_t, 0,
                                  int, uint64_t, uint64_t, uint64_t)
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_memory_unmap, int, -1, int, uint64_t)
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_host_memory_alloc, int, -1,
                                  int, uint64_t, uint64_t*)
UCM_DEFINE_REPLACE_DLSYM_PTR_FUNC(hlthunk_host_memory_free, int, -1,
                                  int, uint64_t)

/* Host memory allocation using hlthunk_malloc */
void* ucm_hlthunk_malloc(size_t size)
{
    void *ptr;
    
    ucm_event_enter();
    ptr = ucm_orig_hlthunk_malloc(size);
    if (ptr != NULL) {
        ucm_trace("hlthunk_malloc(size=%zu) allocated %p", size, ptr);
        ucm_gaudi_dispatch_mem_alloc(ptr, size, UCS_MEMORY_TYPE_HOST);
    }
    ucm_event_leave();
    return ptr;
}

/* Host memory free using hlthunk_free */
int ucm_hlthunk_free(void *ptr)
{
    int ret;
    
    ucm_event_enter();
    ucm_trace("hlthunk_free(ptr=%p)", ptr);
    ucm_gaudi_dispatch_mem_free(ptr, 1, UCS_MEMORY_TYPE_HOST, "hlthunk_free");
    ret = ucm_orig_hlthunk_free(ptr);
    ucm_event_leave();
    return ret;
}

/* Device memory allocation */
uint64_t ucm_hlthunk_device_memory_alloc(int fd, uint64_t size, uint64_t page_size, 
                                         bool contiguous, bool shared)
{
    uint64_t handle;
    
    ucm_event_enter();
    handle = ucm_orig_hlthunk_device_memory_alloc(fd, size, page_size, contiguous, shared);
    if (handle != 0) {
        ucm_trace("hlthunk_device_memory_alloc(fd=%d size=%lu) allocated handle=0x%lx", 
                  fd, size, handle);
        ucm_gaudi_dispatch_mem_alloc((void*)handle, size, UCS_MEMORY_TYPE_UNKNOWN);
    }
    ucm_event_leave();
    return handle;
}

/* Device memory free */
int ucm_hlthunk_device_memory_free(int fd, uint64_t handle, uint64_t size)
{
    int ret;
    
    ucm_event_enter();
    ucm_trace("hlthunk_device_memory_free(fd=%d handle=0x%lx size=%lu)", fd, handle, size);
    ucm_gaudi_dispatch_mem_free((void*)handle, size, UCS_MEMORY_TYPE_UNKNOWN, "hlthunk_device_memory_free");
    ret = ucm_orig_hlthunk_device_memory_free(fd, handle, size);
    ucm_event_leave();
    return ret;
}

/* Device memory mapping */
uint64_t ucm_hlthunk_device_memory_map(int fd, uint64_t handle, uint64_t hint_addr, uint64_t size)
{
    uint64_t addr;
    
    ucm_event_enter();
    addr = ucm_orig_hlthunk_device_memory_map(fd, handle, hint_addr, size);
    if (addr != 0) {
        ucm_trace("hlthunk_device_memory_map(fd=%d handle=0x%lx) mapped to 0x%lx", 
                  fd, handle, addr);
        ucm_gaudi_dispatch_mem_alloc((void*)addr, size, UCS_MEMORY_TYPE_UNKNOWN);
    }
    ucm_event_leave();
    return addr;
}

/* Memory unmapping */
int ucm_hlthunk_memory_unmap(int fd, uint64_t addr)
{
    int ret;
    
    ucm_event_enter();
    ucm_trace("hlthunk_memory_unmap(fd=%d addr=0x%lx)", fd, addr);
    ucm_gaudi_dispatch_mem_free((void*)addr, 1, UCS_MEMORY_TYPE_UNKNOWN, "hlthunk_memory_unmap");
    ret = ucm_orig_hlthunk_memory_unmap(fd, addr);
    ucm_event_leave();
    return ret;
}

/* Host memory allocation (pinned) */
int ucm_hlthunk_host_memory_alloc(int fd, uint64_t size, uint64_t *device_addr)
{
    int ret;
    
    ucm_event_enter();
    ret = ucm_orig_hlthunk_host_memory_alloc(fd, size, device_addr);
    if (ret == 0 && device_addr != NULL) {
        ucm_trace("hlthunk_host_memory_alloc(fd=%d size=%lu) allocated device_addr=0x%lx", 
                  fd, size, *device_addr);
        ucm_gaudi_dispatch_mem_alloc((void*)*device_addr, size, UCS_MEMORY_TYPE_HOST);
    }
    ucm_event_leave();
    return ret;
}

/* Host memory free (pinned) */
int ucm_hlthunk_host_memory_free(int fd, uint64_t device_addr)
{
    int ret;
    
    ucm_event_enter();
    ucm_trace("hlthunk_host_memory_free(fd=%d device_addr=0x%lx)", fd, device_addr);
    ucm_gaudi_dispatch_mem_free((void*)device_addr, 1, UCS_MEMORY_TYPE_HOST, "hlthunk_host_memory_free");
    ret = ucm_orig_hlthunk_host_memory_free(fd, device_addr);
    ucm_event_leave();
    return ret;
}

#define UCM_GAUDI_FUNC_ENTRY(_func) \
    { \
        {#_func, ucm_##_func}, (void**)&ucm_orig_##_func \
    }

typedef struct {
    ucm_reloc_patch_t patch;
    void              **orig_func_ptr;
} ucm_gaudi_func_t;

/* Function patch definitions */
static ucm_gaudi_func_t gaudi_funcs[] = {
    UCM_GAUDI_FUNC_ENTRY(hlthunk_malloc),
    UCM_GAUDI_FUNC_ENTRY(hlthunk_free),
    UCM_GAUDI_FUNC_ENTRY(hlthunk_device_memory_alloc),
    UCM_GAUDI_FUNC_ENTRY(hlthunk_device_memory_free),
    UCM_GAUDI_FUNC_ENTRY(hlthunk_device_memory_map),
    UCM_GAUDI_FUNC_ENTRY(hlthunk_memory_unmap),
    UCM_GAUDI_FUNC_ENTRY(hlthunk_host_memory_alloc),
    UCM_GAUDI_FUNC_ENTRY(hlthunk_host_memory_free),
    {{NULL, NULL}, NULL}
};

static ucs_status_t ucm_gaudimem_install(int events)
{
    static int ucm_gaudimem_installed = 0;
    static pthread_mutex_t install_mutex = PTHREAD_MUTEX_INITIALIZER;
    ucm_gaudi_func_t *func;
    ucs_status_t status = UCS_OK;
    void *func_ptr;

    if (!(events & (UCM_EVENT_MEM_TYPE_ALLOC | UCM_EVENT_MEM_TYPE_FREE))) {
        goto out;
    }

    pthread_mutex_lock(&install_mutex);

    if (ucm_gaudimem_installed) {
        goto out_unlock;
    }

    ucm_debug("installing Gaudi memory hooks");

    for (func = gaudi_funcs; func->patch.symbol != NULL; ++func) {
        func_ptr = ucm_reloc_get_orig(func->patch.symbol, func->patch.value);
        if (func_ptr == NULL) {
            continue;
        }

        status = ucm_reloc_modify(&func->patch);
        if (status != UCS_OK) {
            ucm_warn("failed to install '%s' hook (%s)", func->patch.symbol,
                     ucs_status_string(status));
            goto out_unlock;
        }

        ucm_debug("installed hook for '%s'", func->patch.symbol);
    }

    ucm_gaudimem_installed = 1;

out_unlock:
    pthread_mutex_unlock(&install_mutex);
out:
    return status;
}

static ucm_event_installer_t ucm_gaudi_initializer = {
    .install            = ucm_gaudimem_install,
    .get_existing_alloc = NULL,
};

UCS_STATIC_INIT {
    ucs_list_add_tail(&ucm_event_installer_list, &ucm_gaudi_initializer.list);
}

UCS_STATIC_CLEANUP {
    ucs_list_del(&ucm_gaudi_initializer.list);
}
