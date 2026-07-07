#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "platform/platform.h"

/* Forward declarations — definitions at bottom of file. */
static PlatformError grow_process_list(PlatformProcessEntry **list, unsigned int *capacity, unsigned int n);

/* ---- Public API (order matches platform.h) ---- */

PlatformError platform_list_processes(PlatformProcessEntry **entries, unsigned int *count)
{
    if (!entries || !count) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    *entries = NULL;
    *count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return PLATFORM_ERR_SNAPSHOT_FAILED;
    }

    unsigned int capacity = 64;
    unsigned int n = 0;

    PlatformProcessEntry *list = (PlatformProcessEntry *)HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(PlatformProcessEntry));
    if (!list) {
        CloseHandle(snap);
        return PLATFORM_ERR_INTERNAL;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (n >= capacity) {
                PlatformError err = grow_process_list(&list, &capacity, n);
                if (err != PLATFORM_OK) {
                    CloseHandle(snap);
                    return err;
                }
            }

            list[n].pid = pe.th32ProcessID;
            wcsncpy_s(list[n].name, PLATFORM_NAME_MAX, pe.szExeFile, _TRUNCATE);
            n++;
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    if (n == 0) {
        HeapFree(GetProcessHeap(), 0, list);
        return PLATFORM_OK;
    }

    *entries = list;
    *count = n;
    return PLATFORM_OK;
}

void platform_free_process_list(PlatformProcessEntry *entries)
{
    if (entries) {
        HeapFree(GetProcessHeap(), 0, entries);
    }
}

PlatformError platform_open_process(unsigned int pid, void **out_handle)
{
    if (!out_handle) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    *out_handle = NULL;

    if (pid == 0 || pid == (unsigned int)GetCurrentProcessId()) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    HANDLE handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, (DWORD)pid);

    if (!handle) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            return PLATFORM_ERR_ACCESS_DENIED;
        }
        return PLATFORM_ERR_NOT_FOUND;
    }

    *out_handle = handle;
    return PLATFORM_OK;
}

void platform_close_handle(void *handle)
{
    if (handle) {
        CloseHandle((HANDLE)handle);
    }
}

PlatformError platform_read_memory(void *handle, unsigned long long address, void *buffer, size_t size, size_t *bytes_read)
{
    if (!handle || !buffer || size == 0) {
        if (bytes_read) *bytes_read = 0;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    SIZE_T local_bytes = 0;
    BOOL succeeded = ReadProcessMemory((HANDLE)handle, (LPCVOID)(UINT_PTR)address, buffer, size, &local_bytes);

    if (bytes_read) {
        *bytes_read = (size_t)local_bytes;
    }

    if (!succeeded) {
        if (local_bytes > 0) {
            return PLATFORM_ERR_PARTIAL_READ;
        }
        return PLATFORM_ERR_READ_FAILED;
    }

    return PLATFORM_OK;
}

PlatformError platform_write_memory(void *handle, unsigned long long address, const void *buffer, size_t size, size_t *bytes_written)
{
    if (!handle || !buffer || size == 0) {
        if (bytes_written) *bytes_written = 0;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    SIZE_T local_bytes = 0;
    BOOL succeeded = WriteProcessMemory((HANDLE)handle, (LPVOID)(UINT_PTR)address, buffer, size, &local_bytes);

    if (bytes_written) {
        *bytes_written = (size_t)local_bytes;
    }

    if (!succeeded) {
        if (local_bytes > 0) {
            return PLATFORM_ERR_PARTIAL_WRITE;
        }
        return PLATFORM_ERR_WRITE_FAILED;
    }

    return PLATFORM_OK;
}

PlatformError platform_query_region(void *handle, unsigned long long address, PlatformRegionInfo *info)
{
    if (!handle || !info) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    MEMORY_BASIC_INFORMATION mbi = {0};
    SIZE_T ret = VirtualQueryEx((HANDLE)handle, (LPCVOID)(UINT_PTR)address, &mbi, sizeof(mbi));

    if (ret == 0) {
        return PLATFORM_ERR_QUERY_FAILED;
    }

    info->base    = (unsigned long long)(UINT_PTR)mbi.BaseAddress;
    info->size    = (size_t)mbi.RegionSize;
    info->protect = (unsigned int)mbi.Protect;
    info->state   = (unsigned int)mbi.State;
    info->type    = (unsigned int)mbi.Type;

    return PLATFORM_OK;
}

PlatformError platform_get_main_module(void *handle, PlatformModuleInfo *info)
{
    if (!handle || !info) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    HMODULE modules[1];
    DWORD needed = 0;

    if (!EnumProcessModules((HANDLE)handle, modules, sizeof(modules), &needed)) {
        return PLATFORM_ERR_MODULE_FAILED;
    }

    if (needed == 0) {
        return PLATFORM_ERR_MODULE_FAILED;
    }

    MODULEINFO modInfo = {0};
    if (!GetModuleInformation((HANDLE)handle, modules[0], &modInfo, sizeof(modInfo))) {
        return PLATFORM_ERR_MODULE_FAILED;
    }

    info->base = (unsigned long long)(UINT_PTR)modInfo.lpBaseOfDll;
    info->size = (size_t)modInfo.SizeOfImage;

    DWORD nameLen = GetModuleBaseNameW((HANDLE)handle, modules[0], info->name, PLATFORM_NAME_MAX);
    if (nameLen == 0) {
        return PLATFORM_ERR_MODULE_FAILED;
    }

    return PLATFORM_OK;
}

PlatformError platform_enable_debug_privilege(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return PLATFORM_ERR_PRIVILEGE_FAILED;
    }

    TOKEN_PRIVILEGES tp = {0};
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return PLATFORM_ERR_PRIVILEGE_FAILED;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    /* AdjustTokenPrivileges can return TRUE yet leave the privilege unassigned;
       read GetLastError() before CloseHandle clobbers it. */
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD adjust_error = GetLastError();
    CloseHandle(token);

    if (adjust_error != ERROR_SUCCESS) {
        return PLATFORM_ERR_PRIVILEGE_FAILED;
    }

    return PLATFORM_OK;
}

/* ---- Static helpers ---- */

static PlatformError grow_process_list(PlatformProcessEntry **list, unsigned int *capacity, unsigned int n)
{
    *capacity *= 2;
    PlatformProcessEntry *grown = (PlatformProcessEntry *)HeapAlloc(
        GetProcessHeap(), 0, *capacity * sizeof(PlatformProcessEntry));
    if (!grown) {
        HeapFree(GetProcessHeap(), 0, *list);
        return PLATFORM_ERR_INTERNAL;
    }
    memcpy(grown, *list, n * sizeof(PlatformProcessEntry));
    HeapFree(GetProcessHeap(), 0, *list);
    *list = grown;
    return PLATFORM_OK;
}
