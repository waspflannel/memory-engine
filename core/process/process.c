#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "core/process/process.h"

PlatformError process_list(ProcessEntry **entries, unsigned int *count)
{
    if (!entries || !count) {
        return PLATFORM_ERR_INVALID_PARAM;
    }
     
    PlatformProcessEntry *platform_entries = NULL;
    unsigned int platform_count = 0;

    PlatformError err = platform_list_processes(&platform_entries, &platform_count);
    if (err != PLATFORM_OK) {
        return err;
    }

    if (platform_count == 0) {
        *entries = NULL;
        *count = 0;
        return PLATFORM_OK;
    }

    ProcessEntry *list = (ProcessEntry *)malloc(platform_count * sizeof(ProcessEntry));
    if (!list) {
        platform_free_process_list(platform_entries);
        return PLATFORM_ERR_INTERNAL;
    }

    for (unsigned int i = 0; i < platform_count; i++) {
        list[i].pid = platform_entries[i].pid;
        wcsncpy_s(list[i].name, PROCESS_NAME_MAX, platform_entries[i].name, _TRUNCATE);
    }

    platform_free_process_list(platform_entries);
    *entries = list;
    *count   = platform_count;
    return PLATFORM_OK;
}

void process_free_list(ProcessEntry *entries)
{
    free(entries);
}

void process_target_init(Target *target)
{
    if (target) memset(target, 0, sizeof(*target));
}

PlatformError process_attach(unsigned int pid, Target *target)
{
    if (!target) return PLATFORM_ERR_INVALID_PARAM;
    if (target->handle) return PLATFORM_ERR_INVALID_PARAM;
    process_target_init(target);

    void *handle = NULL;
    PlatformError err = platform_open_process(pid, &handle);
    if (err != PLATFORM_OK) {
        return err;
    }

    target->handle = handle;
    target->pid = pid;

    PlatformModuleInfo module_info = {0};
    err = platform_get_main_module(handle, &module_info);
    if (err != PLATFORM_OK) {
        platform_close_handle(handle);
        memset(target, 0, sizeof(*target));
        return err;
    }

    target->base      = module_info.base;
    target->base_size = module_info.size;
    wcsncpy_s(target->name, PROCESS_NAME_MAX, module_info.name, _TRUNCATE);

    return PLATFORM_OK;
}

void process_detach(Target *target)
{
    if (!target) return;
    if (target->handle) platform_close_handle(target->handle);
    memset(target, 0, sizeof(*target));
}

PlatformError process_is_alive(const Target *target, int *alive)
{
    if (!target || !target->handle || !alive) return PLATFORM_ERR_INVALID_PARAM;
    return platform_process_is_alive(target->handle, alive);
}

PlatformError process_enable_privilege(void)
{
    return platform_enable_debug_privilege();
}

const char *process_error_string(PlatformError err)
{
    switch (err) {
    case PLATFORM_OK:                  return "no error";
    case PLATFORM_ERR_ACCESS_DENIED:   return "access denied (try running as administrator)";
    case PLATFORM_ERR_NOT_FOUND:       return "process not found";
    case PLATFORM_ERR_MODULE_FAILED:   return "failed to query module info";
    case PLATFORM_ERR_INVALID_PARAM:   return "invalid parameter";
    case PLATFORM_ERR_SNAPSHOT_FAILED: return "failed to list processes";
    case PLATFORM_ERR_ENUM_FAILED:     return "process enumeration failed";
    case PLATFORM_ERR_PARTIAL_READ:    return "partial read from target memory";
    case PLATFORM_ERR_READ_FAILED:     return "failed to read target memory";
    case PLATFORM_ERR_PARTIAL_WRITE:   return "partial write to target memory";
    case PLATFORM_ERR_WRITE_FAILED:    return "failed to write target memory";
    case PLATFORM_ERR_QUERY_FAILED:    return "failed to query memory region";
    case PLATFORM_ERR_END_OF_ADDRESS_SPACE: return "end of target address space";
    case PLATFORM_ERR_PRIVILEGE_FAILED: return "failed to enable debug privilege";
    case PLATFORM_ERR_INTERNAL:        return "internal error (out of memory)";
    default:                           return "unknown error";
    }
}
