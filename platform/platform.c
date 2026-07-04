#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "platform/platform.h"

static unsigned int g_plat_last_os_error = 0;
static PlatError    g_plat_last_err    = PLAT_OK;

unsigned int plat_last_os_error(void)
{
    return g_plat_last_os_error;
}

PlatError plat_last_err(void)
{
    return g_plat_last_err;
}

PlatError plat_enable_debug_privilege(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        g_plat_last_err    = PLAT_ERR_PRIVILEGE_FAILED;
        g_plat_last_os_error = (unsigned int)GetLastError();
        return PLAT_ERR_PRIVILEGE_FAILED;
    }

    TOKEN_PRIVILEGES tp = {0};
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        g_plat_last_err    = PLAT_ERR_PRIVILEGE_FAILED;
        g_plat_last_os_error = (unsigned int)GetLastError();
        CloseHandle(token);
        return PLAT_ERR_PRIVILEGE_FAILED;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(token);

    if (err != ERROR_SUCCESS) {
        g_plat_last_err    = PLAT_ERR_PRIVILEGE_FAILED;
        g_plat_last_os_error = (unsigned int)err;
        return PLAT_ERR_PRIVILEGE_FAILED;
    }

    g_plat_last_err = PLAT_OK;
    return PLAT_OK;
}

PlatError plat_enumerate_processes(PlatProcessEntry **entries, unsigned int *count)
{
    if (!entries || !count) {
        g_plat_last_err = PLAT_ERR_INVALID_PARAM;
        return PLAT_ERR_INVALID_PARAM;
    }

    *entries = NULL;
    *count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        g_plat_last_err    = PLAT_ERR_SNAPSHOT_FAILED;
        g_plat_last_os_error = (unsigned int)GetLastError();
        return PLAT_ERR_SNAPSHOT_FAILED;
    }

    unsigned int capacity = 64;
    PlatProcessEntry *list = NULL;
    PlatProcessEntry *temp = NULL;
    unsigned int n = 0;

    list = (PlatProcessEntry *)HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(PlatProcessEntry));
    if (!list) {
        g_plat_last_err    = PLAT_ERR_INTERNAL;
        g_plat_last_os_error = (unsigned int)ERROR_OUTOFMEMORY;
        CloseHandle(snap);
        return PLAT_ERR_INTERNAL;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (n >= capacity) {
                capacity *= 2;
                temp = (PlatProcessEntry *)HeapAlloc(GetProcessHeap(), 0, capacity * sizeof(PlatProcessEntry));
                if (!temp) {
                    HeapFree(GetProcessHeap(), 0, list);
                    CloseHandle(snap);
                    g_plat_last_err    = PLAT_ERR_INTERNAL;
                    g_plat_last_os_error = (unsigned int)ERROR_OUTOFMEMORY;
                    return PLAT_ERR_INTERNAL;
                }
                memcpy(temp, list, n * sizeof(PlatProcessEntry));
                HeapFree(GetProcessHeap(), 0, list);
                list = temp;
            }

            list[n].pid = pe.th32ProcessID;
            wcsncpy_s(list[n].name, 260, pe.szExeFile, _TRUNCATE);
            n++;
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    if (n == 0) {
        HeapFree(GetProcessHeap(), 0, list);
        g_plat_last_err = PLAT_OK;
        return PLAT_OK;
    }

    *entries = list;
    *count = n;
    g_plat_last_err = PLAT_OK;
    return PLAT_OK;
}

void plat_free_process_list(PlatProcessEntry *entries)
{
    if (entries) {
        HeapFree(GetProcessHeap(), 0, entries);
    }
}

PlatError plat_open_process(unsigned int pid, void **handle)
{
    if (!handle) {
        g_plat_last_err = PLAT_ERR_INVALID_PARAM;
        return PLAT_ERR_INVALID_PARAM;
    }

    *handle = NULL;

    if (pid == 0 || pid == (unsigned int)GetCurrentProcessId()) {
        g_plat_last_err    = PLAT_ERR_INVALID_PARAM;
        g_plat_last_os_error = (unsigned int)ERROR_INVALID_PARAMETER;
        return PLAT_ERR_INVALID_PARAM;
    }

    HANDLE h = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, (DWORD)pid);

    if (!h) {
        g_plat_last_os_error = (unsigned int)GetLastError();
        if (g_plat_last_os_error == ERROR_ACCESS_DENIED) {
            g_plat_last_err = PLAT_ERR_ACCESS_DENIED;
            return PLAT_ERR_ACCESS_DENIED;
        }
        g_plat_last_err = PLAT_ERR_NOT_FOUND;
        return PLAT_ERR_NOT_FOUND;
    }

    *handle = h;
    g_plat_last_err = PLAT_OK;
    return PLAT_OK;
}

void plat_close_handle(void *handle)
{
    if (handle) {
        CloseHandle((HANDLE)handle);
    }
}

PlatError plat_read_memory(void *handle, unsigned long long address, void *buffer, size_t size, size_t *bytes_read)
{
    if (!handle || !buffer || size == 0) {
        if (bytes_read) *bytes_read = 0;
        g_plat_last_err = PLAT_ERR_INVALID_PARAM;
        return PLAT_ERR_INVALID_PARAM;
    }

    SIZE_T local_bytes = 0;
    BOOL ok = ReadProcessMemory((HANDLE)handle, (LPCVOID)(UINT_PTR)address, buffer, size, &local_bytes);

    if (bytes_read) {
        *bytes_read = (size_t)local_bytes;
    }

    if (!ok) {
        g_plat_last_os_error = (unsigned int)GetLastError();
        if (local_bytes > 0) {
            g_plat_last_err = PLAT_ERR_PARTIAL_READ;
            return PLAT_ERR_PARTIAL_READ;
        }
        g_plat_last_err = PLAT_ERR_READ_FAILED;
        return PLAT_ERR_READ_FAILED;
    }

    g_plat_last_err = PLAT_OK;
    return PLAT_OK;
}

PlatError plat_write_memory(void *handle, unsigned long long address, const void *buffer, size_t size, size_t *bytes_written)
{
    if (!handle || !buffer || size == 0) {
        if (bytes_written) *bytes_written = 0;
        g_plat_last_err = PLAT_ERR_INVALID_PARAM;
        return PLAT_ERR_INVALID_PARAM;
    }

    SIZE_T local_bytes = 0;
    BOOL ok = WriteProcessMemory((HANDLE)handle, (LPVOID)(UINT_PTR)address, buffer, size, &local_bytes);

    if (bytes_written) {
        *bytes_written = (size_t)local_bytes;
    }

    if (!ok) {
        g_plat_last_os_error = (unsigned int)GetLastError();
        if (local_bytes > 0) {
            g_plat_last_err = PLAT_ERR_PARTIAL_WRITE;
            return PLAT_ERR_PARTIAL_WRITE;
        }
        g_plat_last_err = PLAT_ERR_WRITE_FAILED;
        return PLAT_ERR_WRITE_FAILED;
    }

    g_plat_last_err = PLAT_OK;
    return PLAT_OK;
}

PlatError plat_query_region(void *handle, unsigned long long address, PlatRegionInfo *info)
{
    if (!handle || !info) {
        g_plat_last_err = PLAT_ERR_INVALID_PARAM;
        return PLAT_ERR_INVALID_PARAM;
    }

    MEMORY_BASIC_INFORMATION mbi = {0};
    SIZE_T ret = VirtualQueryEx((HANDLE)handle, (LPCVOID)(UINT_PTR)address, &mbi, sizeof(mbi));

    if (ret == 0) {
        g_plat_last_err    = PLAT_ERR_QUERY_FAILED;
        g_plat_last_os_error = (unsigned int)GetLastError();
        return PLAT_ERR_QUERY_FAILED;
    }

    info->base    = (unsigned long long)(UINT_PTR)mbi.BaseAddress;
    info->size    = (size_t)mbi.RegionSize;
    info->protect = (unsigned int)mbi.Protect;
    info->state   = (unsigned int)mbi.State;
    info->type    = (unsigned int)mbi.Type;

    g_plat_last_err = PLAT_OK;
    return PLAT_OK;
}

PlatError plat_get_main_module(void *handle, PlatModuleInfo *info)
{
    if (!handle || !info) {
        g_plat_last_err = PLAT_ERR_INVALID_PARAM;
        return PLAT_ERR_INVALID_PARAM;
    }

    HMODULE modules[1];
    DWORD needed = 0;

    if (!EnumProcessModules((HANDLE)handle, modules, sizeof(modules), &needed)) {
        g_plat_last_err    = PLAT_ERR_MODULE_FAILED;
        g_plat_last_os_error = (unsigned int)GetLastError();
        return PLAT_ERR_MODULE_FAILED;
    }

    if (needed == 0) {
        g_plat_last_err    = PLAT_ERR_MODULE_FAILED;
        g_plat_last_os_error = (unsigned int)ERROR_NOT_FOUND;
        return PLAT_ERR_MODULE_FAILED;
    }

    MODULEINFO modInfo = {0};
    if (!GetModuleInformation((HANDLE)handle, modules[0], &modInfo, sizeof(modInfo))) {
        g_plat_last_err    = PLAT_ERR_MODULE_FAILED;
        g_plat_last_os_error = (unsigned int)GetLastError();
        return PLAT_ERR_MODULE_FAILED;
    }

    info->base = (unsigned long long)(UINT_PTR)modInfo.lpBaseOfDll;
    info->size = (size_t)modInfo.SizeOfImage;

    DWORD nameLen = GetModuleBaseNameW((HANDLE)handle, modules[0], info->name, 260);
    if (nameLen == 0) {
        g_plat_last_err    = PLAT_ERR_MODULE_FAILED;
        g_plat_last_os_error = (unsigned int)GetLastError();
        return PLAT_ERR_MODULE_FAILED;
    }

    g_plat_last_err = PLAT_OK;
    return PLAT_OK;
}
