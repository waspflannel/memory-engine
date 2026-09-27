#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>

#define PLATFORM_NAME_MAX 260

typedef enum {
    PLATFORM_OK = 0,
    PLATFORM_ERR_ACCESS_DENIED,
    PLATFORM_ERR_NOT_FOUND,
    PLATFORM_ERR_PARTIAL_READ,
    PLATFORM_ERR_PARTIAL_WRITE,
    PLATFORM_ERR_READ_FAILED,
    PLATFORM_ERR_WRITE_FAILED,
    PLATFORM_ERR_INVALID_PARAM,
    PLATFORM_ERR_QUERY_FAILED,
    PLATFORM_ERR_END_OF_ADDRESS_SPACE,
    PLATFORM_ERR_SNAPSHOT_FAILED,
    PLATFORM_ERR_ENUM_FAILED,
    PLATFORM_ERR_MODULE_FAILED,
    PLATFORM_ERR_PRIVILEGE_FAILED,
    PLATFORM_ERR_INTERNAL,
} PlatformError;

typedef struct {
    unsigned int  pid;
    wchar_t       name[PLATFORM_NAME_MAX];
} PlatformProcessEntry;

typedef struct {
    unsigned long long base;
    size_t             size;
    unsigned int       protect;
    unsigned int       state;
} PlatformRegionInfo;

typedef struct {
    unsigned long long base;
    size_t             size;
    wchar_t            name[PLATFORM_NAME_MAX];
} PlatformModuleInfo;

PlatformError  platform_list_processes(PlatformProcessEntry **entries, unsigned int *count);
void           platform_free_process_list(PlatformProcessEntry *entries);

PlatformError  platform_open_process(unsigned int pid, void **out_handle);
void           platform_close_handle(void *handle);
PlatformError  platform_process_is_alive(void *handle, int *alive);

PlatformError  platform_read_memory(void *handle, unsigned long long address, void *buffer, size_t size, size_t *bytes_read);
PlatformError  platform_write_memory(void *handle, unsigned long long address, const void *buffer, size_t size, size_t *bytes_written);

PlatformError  platform_query_region(void *handle, unsigned long long address, PlatformRegionInfo *info);

PlatformError  platform_get_main_module(void *handle, PlatformModuleInfo *info);

PlatformError  platform_enable_debug_privilege(void);

#endif
