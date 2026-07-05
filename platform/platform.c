#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "platform/platform.h"

static unsigned int  s_last_os_error = 0;
static PlatformError s_last_error    = PLATFORM_OK;

unsigned int platform_last_os_error(void)
{
    return s_last_os_error;
}

PlatformError platform_last_error(void)
{
    return s_last_error;
}

PlatformError platform_enable_debug_privilege(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        s_last_error    = PLATFORM_ERR_PRIVILEGE_FAILED;
        s_last_os_error = (unsigned int)GetLastError();
        return PLATFORM_ERR_PRIVILEGE_FAILED;
    }

    TOKEN_PRIVILEGES tp = {0};
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        s_last_error    = PLATFORM_ERR_PRIVILEGE_FAILED;
        s_last_os_error = (unsigned int)GetLastError();
        CloseHandle(token);
        return PLATFORM_ERR_PRIVILEGE_FAILED;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(token);

    if (err != ERROR_SUCCESS) {
        s_last_error    = PLATFORM_ERR_PRIVILEGE_FAILED;
        s_last_os_error = (unsigned int)err;
        return PLATFORM_ERR_PRIVILEGE_FAILED;
    }

    s_last_error = PLATFORM_OK;
    return PLATFORM_OK;
}

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
        s_last_error    = PLATFORM_ERR_SNAPSHOT_FAILED;
        s_last_os_error = (unsigned int)GetLastError();
        return PLATFORM_ERR_SNAPSHOT_FAILED;
    }

    unsigned int capacity = 64;
    PlatformProcessEntry *list = NULL;
    PlatformProcessEntry *temp = NULL;
    unsigned int n = 0;

    list = (PlatformProcessEntry *)HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(PlatformProcessEntry));
    if (!list) {
        s_last_error    = PLATFORM_ERR_INTERNAL;
        s_last_os_error = (unsigned int)ERROR_OUTOFMEMORY;
        CloseHandle(snap);
        return PLATFORM_ERR_INTERNAL;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (n >= capacity) {
                capacity *= 2;
                temp = (PlatformProcessEntry *)HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(PlatformProcessEntry));
                if (!temp) {
                    HeapFree(GetProcessHeap(), 0, list);
                    CloseHandle(snap);
                    s_last_error    = PLATFORM_ERR_INTERNAL;
                    s_last_os_error = (unsigned int)ERROR_OUTOFMEMORY;
                    return PLATFORM_ERR_INTERNAL;
                }
                memcpy(temp, list, n * sizeof(PlatformProcessEntry));
                HeapFree(GetProcessHeap(), 0, list);
                list = temp;
            }

            list[n].pid = pe.th32ProcessID;
            wcsncpy_s(list[n].name, PLATFORM_NAME_MAX, pe.szExeFile, _TRUNCATE);
            n++;
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    if (n == 0) {
        HeapFree(GetProcessHeap(), 0, list);
        s_last_error = PLATFORM_OK;
        return PLATFORM_OK;
    }

    *entries = list;
    *count = n;
    s_last_error = PLATFORM_OK;
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
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    *out_handle = NULL;

    if (pid == 0 || pid == (unsigned int)GetCurrentProcessId()) {
        s_last_error    = PLATFORM_ERR_INVALID_PARAM;
        s_last_os_error = (unsigned int)ERROR_INVALID_PARAMETER;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    HANDLE handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, (DWORD)pid);

    if (!handle) {
        s_last_os_error = (unsigned int)GetLastError();
        if (s_last_os_error == ERROR_ACCESS_DENIED) {
            s_last_error = PLATFORM_ERR_ACCESS_DENIED;
            return PLATFORM_ERR_ACCESS_DENIED;
        }
        s_last_error = PLATFORM_ERR_NOT_FOUND;
        return PLATFORM_ERR_NOT_FOUND;
    }

    *out_handle = handle;
    s_last_error = PLATFORM_OK;
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
        s_last_error = PLATFORM_ERR_INVALID_PARAM;
        return PLATFORM_ERR_INVALID_PARAM;
    }

    SIZE_T local_bytes = 0;
    BOOL succeeded = ReadProcessMemory((HANDLE)handle, (LPCVOID)(UINT_PTR)address, buffer, size, &local_bytes);

    if (bytes_read) {
        *bytes_read = (size_t)local_bytes;
    }

    if (!succeeded) {
        s_last_os_error = (unsigned int)GetLastError();
        if (local_bytes > 0) {
            s_last_error = PLATFORM_ERR_PARTIAL_READ;
            return PLATFORM_ERR_PARTIAL_READ;
        }
        s_last_error = PLATFORM_ERR_READ_FAILED;
        return PLATFORM_ERR_READ_FAILED;
    }

    s_last_error = PLATFORM_OK;
    return PLATFORM_OK;
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
        s_last_os_error = (unsigned int)GetLastError();
        if (local_bytes > 0) {
            s_last_error = PLATFORM_ERR_PARTIAL_WRITE;
            return PLATFORM_ERR_PARTIAL_WRITE;
        }
        s_last_error = PLATFORM_ERR_WRITE_FAILED;
        return PLATFORM_ERR_WRITE_FAILED;
    }

    s_last_error = PLATFORM_OK;
    return PLATFORM_OK;
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
        s_last_error    = PLATFORM_ERR_QUERY_FAILED;
        s_last_os_error = (unsigned int)GetLastError();
        return PLATFORM_ERR_QUERY_FAILED;
    }

    info->base    = (unsigned long long)(UINT_PTR)mbi.BaseAddress;
    info->size    = (size_t)mbi.RegionSize;
    info->protect = (unsigned int)mbi.Protect;
    info->state   = (unsigned int)mbi.State;
    info->type    = (unsigned int)mbi.Type;

    s_last_error = PLATFORM_OK;
    return PLATFORM_OK;
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
        s_last_error    = PLATFORM_ERR_MODULE_FAILED;
        s_last_os_error = (unsigned int)GetLastError();
        return PLATFORM_ERR_MODULE_FAILED;
    }

    if (needed == 0) {
        s_last_error    = PLATFORM_ERR_MODULE_FAILED;
        s_last_os_error = (unsigned int)ERROR_NOT_FOUND;
        return PLATFORM_ERR_MODULE_FAILED;
    }

    MODULEINFO modInfo = {0};
    if (!GetModuleInformation((HANDLE)handle, modules[0], &modInfo, sizeof(modInfo))) {
        s_last_error    = PLATFORM_ERR_MODULE_FAILED;
        s_last_os_error = (unsigned int)GetLastError();
        return PLATFORM_ERR_MODULE_FAILED;
    }

    info->base = (unsigned long long)(UINT_PTR)modInfo.lpBaseOfDll;
    info->size = (size_t)modInfo.SizeOfImage;

    DWORD nameLen = GetModuleBaseNameW((HANDLE)handle, modules[0], info->name, PLATFORM_NAME_MAX);
    if (nameLen == 0) {
        s_last_error    = PLATFORM_ERR_MODULE_FAILED;
        s_last_os_error = (unsigned int)GetLastError();
        return PLATFORM_ERR_MODULE_FAILED;
    }

    s_last_error = PLATFORM_OK;
    return PLATFORM_OK;
}
