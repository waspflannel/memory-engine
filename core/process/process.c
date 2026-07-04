#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include "core/process/process.h"
#include "platform/platform.h"

int proc_enumerate(ProcessEntry **entries, unsigned int *count)
{
    PlatProcessEntry *plat_entries = NULL;
    unsigned int plat_count = 0;

    PlatError err = plat_enumerate_processes(&plat_entries, &plat_count);
    if (err != PLAT_OK) {
        return -1;
    }

    ProcessEntry *list = (ProcessEntry *)HeapAlloc(GetProcessHeap(), 0,
        plat_count * sizeof(ProcessEntry));
    if (!list) {
        plat_free_process_list(plat_entries);
        return -1;
    }

    for (unsigned int i = 0; i < plat_count; i++) {
        list[i].pid = plat_entries[i].pid;
        wcsncpy_s(list[i].name, PROC_NAME_MAX, plat_entries[i].name, _TRUNCATE);
    }

    plat_free_process_list(plat_entries);
    *entries = list;
    *count   = plat_count;
    return 0;
}

void proc_free_list(ProcessEntry *entries)
{
    if (entries) {
        HeapFree(GetProcessHeap(), 0, entries);
    }
}

int proc_attach(unsigned int pid, Target *target)
{
    if (!target) return -1;

    memset(target, 0, sizeof(*target));

    void *h = NULL;
    PlatError err = plat_open_process(pid, &h);
    if (err != PLAT_OK) {
        return -1;
    }

    target->handle = h;
    target->pid = pid;

    PlatModuleInfo modInfo = {0};
    err = plat_get_main_module(pid, h, &modInfo);
    if (err != PLAT_OK) {
        plat_close_handle(h);
        target->handle = NULL;
        return -1;
    }

    target->base      = modInfo.base;
    target->base_size = modInfo.size;
    wcsncpy_s(target->name, PROC_NAME_MAX, modInfo.name, _TRUNCATE);

    return 0;
}

void proc_detach(Target *target)
{
    if (target && target->handle) {
        plat_close_handle(target->handle);
        memset(target, 0, sizeof(*target));
    }
}

int proc_last_error(void)
{
    return (int)plat_last_error();
}

const char *proc_last_error_string(void)
{
    switch (plat_last_error()) {
    case PLAT_ERR_ACCESS_DENIED:  return "access denied (try running as administrator)";
    case PLAT_ERR_NOT_FOUND:      return "process not found";
    case PLAT_ERR_MODULE_FAILED:  return "failed to query module info";
    case PLAT_ERR_INVALID_PARAM:  return "invalid parameter";
    case PLAT_ERR_SNAPSHOT_FAILED: return "failed to enumerate processes";
    default:                      return "unknown error";
    }
}
