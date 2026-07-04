#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "core/process/process.h"

PlatError proc_enumerate(ProcessEntry **entries, unsigned int *count)
{
    PlatProcessEntry *plat_entries = NULL;
    unsigned int plat_count = 0;

    PlatError err = plat_enumerate_processes(&plat_entries, &plat_count);
    if (err != PLAT_OK) {
        return err;
    }

    ProcessEntry *list = (ProcessEntry *)malloc(plat_count * sizeof(ProcessEntry));
    if (!list) {
        plat_free_process_list(plat_entries);
        return PLAT_ERR_INTERNAL;
    }

    for (unsigned int i = 0; i < plat_count; i++) {
        list[i].pid = plat_entries[i].pid;
        wcsncpy(list[i].name, plat_entries[i].name, PROC_NAME_MAX - 1);
        list[i].name[PROC_NAME_MAX - 1] = L'\0';
    }

    plat_free_process_list(plat_entries);
    *entries = list;
    *count   = plat_count;
    return PLAT_OK;
}

void proc_free_list(ProcessEntry *entries)
{
    free(entries);
}

PlatError proc_attach(unsigned int pid, Target *target)
{
    if (!target) return PLAT_ERR_INVALID_PARAM;

    memset(target, 0, sizeof(*target));

    void *h = NULL;
    PlatError err = plat_open_process(pid, &h);
    if (err != PLAT_OK) {
        return err;
    }

    target->handle = h;
    target->pid = pid;

    PlatModuleInfo modInfo = {0};
    err = plat_get_main_module(h, &modInfo);
    if (err != PLAT_OK) {
        plat_close_handle(h);
        target->handle = NULL;
        return err;
    }

    target->base      = modInfo.base;
    target->base_size = modInfo.size;
    wcsncpy(target->name, modInfo.name, PROC_NAME_MAX - 1);
    target->name[PROC_NAME_MAX - 1] = L'\0';

    return PLAT_OK;
}

void proc_detach(Target *target)
{
    if (target && target->handle) {
        plat_close_handle(target->handle);
        memset(target, 0, sizeof(*target));
    }
}

PlatError proc_enable_privilege(void)
{
    return plat_enable_debug_privilege();
}

int proc_last_error(void)
{
    return (int)plat_last_error();
}

const char *proc_last_error_string(void)
{
    switch (plat_last_err()) {
    case PLAT_ERR_ACCESS_DENIED:   return "access denied (try running as administrator)";
    case PLAT_ERR_NOT_FOUND:       return "process not found";
    case PLAT_ERR_MODULE_FAILED:   return "failed to query module info";
    case PLAT_ERR_INVALID_PARAM:   return "invalid parameter";
    case PLAT_ERR_SNAPSHOT_FAILED: return "failed to enumerate processes";
    case PLAT_ERR_PARTIAL_READ:    return "partial read from target memory";
    case PLAT_ERR_READ_FAILED:     return "failed to read target memory";
    case PLAT_ERR_PARTIAL_WRITE:   return "partial write to target memory";
    case PLAT_ERR_WRITE_FAILED:     return "failed to write target memory";
    case PLAT_ERR_QUERY_FAILED:    return "failed to query memory region";
    case PLAT_ERR_PRIVILEGE_FAILED: return "failed to enable debug privilege";
    case PLAT_ERR_INTERNAL:        return "internal error (out of memory)";
    default:                       return "unknown error";
    }
}
