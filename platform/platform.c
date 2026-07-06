#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "platform/platform.h"

static unsigned int  s_last_os_error = 0;
static PlatformError s_last_error    = PLATFORM_OK;

/* Forward declarations — definitions at bottom of file. */
static PlatformError fail(PlatformError err);
static PlatformError fail_with_os(PlatformError err, unsigned int os_err);
static PlatformError succeed(void);
static PlatformError grow_process_list(PlatformProcessEntry **list, unsigned int *capacity, unsigned int n);

/* ---- Public API (order matches platform.h) ---- */

PlatformError platform_list_processes(PlatformProcessEntry **entries, unsigned int *count)
{
    if (!entries || !count) {
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    *entries = NULL;
    *count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return fail(PLATFORM_ERR_SNAPSHOT_FAILED);
    }

    unsigned int capacity = 64;
    unsigned int n = 0;

    PlatformProcessEntry *list = (PlatformProcessEntry *)HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(PlatformProcessEntry));
    if (!list) {
        CloseHandle(snap);
        return fail_with_os(PLATFORM_ERR_INTERNAL, ERROR_OUTOFMEMORY);
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
        return succeed();
    }

    *entries = list;
    *count = n;
    return succeed();
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
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    *out_handle = NULL;

    if (pid == 0 || pid == (unsigned int)GetCurrentProcessId()) {
        return fail_with_os(PLATFORM_ERR_INVALID_PARAM, ERROR_INVALID_PARAMETER);
    }

    HANDLE handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, (DWORD)pid);

    if (!handle) {
        DWORD os_err = GetLastError();
        if (os_err == ERROR_ACCESS_DENIED) {
            return fail_with_os(PLATFORM_ERR_ACCESS_DENIED, os_err);
        }
        return fail_with_os(PLATFORM_ERR_NOT_FOUND, os_err);
    }

    *out_handle = handle;
    return succeed();
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
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    SIZE_T local_bytes = 0;
    BOOL succeeded = ReadProcessMemory((HANDLE)handle, (LPCVOID)(UINT_PTR)address, buffer, size, &local_bytes);

    if (bytes_read) {
        *bytes_read = (size_t)local_bytes;
    }

    if (!succeeded) {
        if (local_bytes > 0) {
            return fail(PLATFORM_ERR_PARTIAL_READ);
        }
        return fail(PLATFORM_ERR_READ_FAILED);
    }

    return succeed();
}

PlatformError platform_write_memory(void *handle, unsigned long long address, const void *buffer, size_t size, size_t *bytes_written)
{
    if (!handle || !buffer || size == 0) {
        if (bytes_written) *bytes_written = 0;
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    SIZE_T local_bytes = 0;
    BOOL succeeded = WriteProcessMemory((HANDLE)handle, (LPVOID)(UINT_PTR)address, buffer, size, &local_bytes);

    if (bytes_written) {
        *bytes_written = (size_t)local_bytes;
    }

    if (!succeeded) {
        if (local_bytes > 0) {
            return fail(PLATFORM_ERR_PARTIAL_WRITE);
        }
        return fail(PLATFORM_ERR_WRITE_FAILED);
    }

    return succeed();
}

PlatformError platform_query_region(void *handle, unsigned long long address, PlatformRegionInfo *info)
{
    if (!handle || !info) {
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    MEMORY_BASIC_INFORMATION mbi = {0};
    SIZE_T ret = VirtualQueryEx((HANDLE)handle, (LPCVOID)(UINT_PTR)address, &mbi, sizeof(mbi));

    if (ret == 0) {
        return fail(PLATFORM_ERR_QUERY_FAILED);
    }

    info->base    = (unsigned long long)(UINT_PTR)mbi.BaseAddress;
    info->size    = (size_t)mbi.RegionSize;
    info->protect = (unsigned int)mbi.Protect;
    info->state   = (unsigned int)mbi.State;
    info->type    = (unsigned int)mbi.Type;

    return succeed();
}

PlatformError platform_get_main_module(void *handle, PlatformModuleInfo *info)
{
    if (!handle || !info) {
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    HMODULE modules[1];
    DWORD needed = 0;

    if (!EnumProcessModules((HANDLE)handle, modules, sizeof(modules), &needed)) {
        return fail(PLATFORM_ERR_MODULE_FAILED);
    }

    if (needed == 0) {
        return fail_with_os(PLATFORM_ERR_MODULE_FAILED, ERROR_NOT_FOUND);
    }

    MODULEINFO modInfo = {0};
    if (!GetModuleInformation((HANDLE)handle, modules[0], &modInfo, sizeof(modInfo))) {
        return fail(PLATFORM_ERR_MODULE_FAILED);
    }

    info->base = (unsigned long long)(UINT_PTR)modInfo.lpBaseOfDll;
    info->size = (size_t)modInfo.SizeOfImage;

    DWORD nameLen = GetModuleBaseNameW((HANDLE)handle, modules[0], info->name, PLATFORM_NAME_MAX);
    if (nameLen == 0) {
        return fail(PLATFORM_ERR_MODULE_FAILED);
    }

    return succeed();
}

PlatformError platform_enable_debug_privilege(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return fail(PLATFORM_ERR_PRIVILEGE_FAILED);
    }

    TOKEN_PRIVILEGES tp = {0};
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        DWORD os_err = GetLastError();
        CloseHandle(token);
        return fail_with_os(PLATFORM_ERR_PRIVILEGE_FAILED, os_err);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(token);

    if (err != ERROR_SUCCESS) {
        return fail_with_os(PLATFORM_ERR_PRIVILEGE_FAILED, err);
    }

    return succeed();
}

unsigned int platform_last_os_error(void)
{
    return s_last_os_error;
}

PlatformError platform_last_error(void)
{
    return s_last_error;
}

/* ---- Static helpers ---- */

static PlatformError fail(PlatformError err)
{
    s_last_error    = err;
    s_last_os_error = (unsigned int)GetLastError();
    return err;
}

static PlatformError fail_with_os(PlatformError err, unsigned int os_err)
{
    s_last_error    = err;
    s_last_os_error = os_err;
    return err;
}

static PlatformError succeed(void)
{
    s_last_error = PLATFORM_OK;
    return PLATFORM_OK;
}

static PlatformError grow_process_list(PlatformProcessEntry **list, unsigned int *capacity, unsigned int n)
{
    *capacity *= 2;
    PlatformProcessEntry *grown = (PlatformProcessEntry *)HeapAlloc(
        GetProcessHeap(), 0, *capacity * sizeof(PlatformProcessEntry));
    if (!grown) {
        HeapFree(GetProcessHeap(), 0, *list);
        return fail_with_os(PLATFORM_ERR_INTERNAL, ERROR_OUTOFMEMORY);
    }
    memcpy(grown, *list, n * sizeof(PlatformProcessEntry));
    HeapFree(GetProcessHeap(), 0, *list);
    *list = grown;
    return succeed();
}
