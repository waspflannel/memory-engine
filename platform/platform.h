#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>

typedef enum {
    PLAT_OK = 0,
    PLAT_ERR_ACCESS_DENIED,
    PLAT_ERR_NOT_FOUND,
    PLAT_ERR_PARTIAL_READ,
    PLAT_ERR_PARTIAL_WRITE,
    PLAT_ERR_READ_FAILED,
    PLAT_ERR_WRITE_FAILED,
    PLAT_ERR_INVALID_PARAM,
    PLAT_ERR_QUERY_FAILED,
    PLAT_ERR_SNAPSHOT_FAILED,
    PLAT_ERR_MODULE_FAILED,
    PLAT_ERR_PRIVILEGE_FAILED,
    PLAT_ERR_INTERNAL,
} PlatError;

typedef struct {
    unsigned int  pid;
    wchar_t       name[260];
} PlatProcessEntry;

typedef struct {
    unsigned long long base;
    size_t             size;
    unsigned int       protect;
    unsigned int       state;
    unsigned int       type;
} PlatRegionInfo;

typedef struct {
    unsigned long long base;
    size_t             size;
    wchar_t            name[260];
} PlatModuleInfo;

PlatError  plat_enumerate_processes(PlatProcessEntry **entries, unsigned int *count);
void       plat_free_process_list(PlatProcessEntry *entries);

PlatError  plat_open_process(unsigned int pid, void **handle);
void       plat_close_handle(void *handle);

PlatError  plat_read_memory(void *handle, unsigned long long address, void *buffer, size_t size, size_t *bytes_read);
PlatError  plat_write_memory(void *handle, unsigned long long address, const void *buffer, size_t size, size_t *bytes_written);

PlatError  plat_query_region(void *handle, unsigned long long address, PlatRegionInfo *info);

PlatError  plat_get_main_module(void *handle, PlatModuleInfo *info);

PlatError  plat_enable_debug_privilege(void);

unsigned int plat_last_error(void);
PlatError    plat_last_err(void);

#endif
