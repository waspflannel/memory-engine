#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdlib.h>
#include <wchar.h>
#include "platform/injector.h"

struct PlatformInjection {
    HANDLE process, thread, file;
    void *argument;
    unsigned int pid;
    wchar_t path[MAX_PATH]; /* ponytail: long-path support when a real DLL path needs it. */
};

static InjectionError validate_dll(PlatformInjection *injection, const wchar_t *path);
static InjectionError find_module(HANDLE process, unsigned int pid, const wchar_t *name, int full_path,
                                  unsigned long long *base, DWORD *size);
static InjectionError loader_address(HANDLE process, unsigned int pid, LPTHREAD_START_ROUTINE *entry);

InjectionError platform_inject_start(unsigned int pid, const wchar_t *path, PlatformInjection **out)
{
    PlatformInjection *injection;
    InjectionError error;
    LPTHREAD_START_ROUTINE entry;
    BOOL wow64;
    SYSTEM_INFO system;
    SIZE_T bytes, written;
    if (!out || *out || !path || !*path || !pid || pid == GetCurrentProcessId()) return INJECTION_ERR_INVALID;
    injection = calloc(1, sizeof(*injection));
    if (!injection) return INJECTION_ERR_MEMORY;
    injection->file = INVALID_HANDLE_VALUE;
    injection->pid = pid;
    error = validate_dll(injection, path);
    if (error != INJECTION_OK) goto fail;
    injection->process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid);
    if (!injection->process) { error = INJECTION_ERR_ACCESS; goto fail; }
    GetNativeSystemInfo(&system);
    if (!IsWow64Process(injection->process, &wow64)) { error = INJECTION_ERR_ACCESS; goto fail; }
    if (wow64 || system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
        error = INJECTION_ERR_ARCHITECTURE; goto fail;
    }
    error = loader_address(injection->process, pid, &entry);
    if (error != INJECTION_OK) goto fail;
    bytes = (wcslen(injection->path) + 1) * sizeof(wchar_t);
    injection->argument = VirtualAllocEx(injection->process, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!injection->argument) { error = INJECTION_ERR_MEMORY; goto fail; }
    if (!WriteProcessMemory(injection->process, injection->argument, injection->path, bytes, &written) || written != bytes) {
        error = INJECTION_ERR_WRITE; goto fail;
    }
    injection->thread = CreateRemoteThread(injection->process, NULL, 0, entry, injection->argument, 0, NULL);
    if (!injection->thread) { error = INJECTION_ERR_THREAD; goto fail; }
    *out = injection;
    return INJECTION_OK;
fail:
    /* No remote thread exists on these paths. Preserve ownership if freeing fails. */
    *out = injection;
    if (platform_inject_release(out) != INJECTION_OK) return INJECTION_ERR_CLEANUP;
    return error;
}

InjectionError platform_inject_poll(PlatformInjection *injection, int *complete, unsigned long long *module_base)
{
    DWORD wait, size;
    if (!injection || !complete || !module_base) return INJECTION_ERR_INVALID;
    *complete = 0;
    *module_base = 0;
    if (!injection->thread) { *complete = 1; return INJECTION_ERR_CLEANUP; }
    wait = WaitForSingleObject(injection->thread, 0);
    if (wait == WAIT_TIMEOUT) return INJECTION_OK;
    if (wait != WAIT_OBJECT_0) return INJECTION_ERR_WAIT;
    *complete = 1;
    if (WaitForSingleObject(injection->process, 0) == WAIT_OBJECT_0) return INJECTION_ERR_LOAD;
    return find_module(injection->process, injection->pid, injection->path, 1, module_base, &size);
}

InjectionError platform_inject_release(PlatformInjection **owner)
{
    PlatformInjection *injection;
    if (!owner || !*owner) return INJECTION_OK;
    injection = *owner;
    if (injection->thread) {
        DWORD wait = WaitForSingleObject(injection->thread, 0);
        if (wait == WAIT_TIMEOUT) return INJECTION_ERR_BUSY;
        if (wait != WAIT_OBJECT_0) return INJECTION_ERR_WAIT;
    }
    if (injection->argument && !VirtualFreeEx(injection->process, injection->argument, 0, MEM_RELEASE) &&
        WaitForSingleObject(injection->process, 0) != WAIT_OBJECT_0) return INJECTION_ERR_CLEANUP;
    if (injection->thread) CloseHandle(injection->thread);
    if (injection->process) CloseHandle(injection->process);
    if (injection->file != INVALID_HANDLE_VALUE) CloseHandle(injection->file);
    free(injection);
    *owner = NULL;
    return INJECTION_OK;
}

const char *platform_inject_error_string(InjectionError error)
{
    switch (error) {
    case INJECTION_OK: return "DLL loaded";
    case INJECTION_ERR_INVALID: return "Invalid injection target or path";
    case INJECTION_ERR_PATH: return "DLL path missing, inaccessible, or too long (maximum 259 characters)";
    case INJECTION_ERR_NOT_DLL: return "File is not a valid PE DLL";
    case INJECTION_ERR_ARCHITECTURE: return "DLL injection requires a native x64 target and DLL";
    case INJECTION_ERR_ACCESS: return "Cannot open target with injection rights";
    case INJECTION_ERR_MODULES: return "Cannot resolve or enumerate target modules";
    case INJECTION_ERR_MEMORY: return "Cannot allocate injection memory";
    case INJECTION_ERR_WRITE: return "Cannot write DLL path into target";
    case INJECTION_ERR_THREAD: return "Cannot start target loader thread";
    case INJECTION_ERR_WAIT: return "Cannot query target loader thread";
    case INJECTION_ERR_LOAD: return "DLL not loaded (loader rejected it or target exited)";
    case INJECTION_ERR_BUSY: return "DLL loader still running; wait before detaching";
    case INJECTION_ERR_CLEANUP: return "Cannot release injection memory; retry cleanup";
    default: return "Unknown injection error";
    }
}

static InjectionError validate_dll(PlatformInjection *injection, const wchar_t *path)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    LARGE_INTEGER length, offset;
    DWORD count, path_length;
    path_length = GetFullPathNameW(path, MAX_PATH, injection->path, NULL);
    if (!path_length || path_length >= MAX_PATH) return INJECTION_ERR_PATH;
    injection->file = CreateFileW(injection->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (injection->file == INVALID_HANDLE_VALUE) return INJECTION_ERR_PATH;
    if (!GetFileSizeEx(injection->file, &length) ||
        !ReadFile(injection->file, &dos, sizeof(dos), &count, NULL) || count != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < (LONG)sizeof(dos) ||
        (LONGLONG)dos.e_lfanew + sizeof(nt) > (ULONGLONG)length.QuadPart) return INJECTION_ERR_NOT_DLL;
    offset.QuadPart = dos.e_lfanew;
    if (!SetFilePointerEx(injection->file, offset, NULL, FILE_BEGIN) ||
        !ReadFile(injection->file, &nt, sizeof(nt), &count, NULL) || count != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || !(nt.FileHeader.Characteristics & IMAGE_FILE_DLL)) return INJECTION_ERR_NOT_DLL;
    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return INJECTION_ERR_ARCHITECTURE;
    if (nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return INJECTION_ERR_NOT_DLL;
    return INJECTION_OK;
}

static InjectionError find_module(HANDLE process, unsigned int pid, const wchar_t *name, int full_path,
                                  unsigned long long *base, DWORD *size)
{
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W module = {0};
    InjectionError error = full_path ? INJECTION_ERR_LOAD : INJECTION_ERR_MODULES;
    /* Toolhelp explicitly requests a retry when a concurrent loader changes the list. */
    for (unsigned int attempt = 0; attempt < 3; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (snapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
    }
    if (snapshot == INVALID_HANDLE_VALUE) return INJECTION_ERR_MODULES;
    module.dwSize = sizeof(module);
    if (Module32FirstW(snapshot, &module)) {
        do {
            wchar_t path[MAX_PATH];
            const wchar_t *candidate = module.szModule;
            if (full_path) {
                /* Toolhelp paths can lose non-ANSI characters, even through its W API. */
                DWORD length = GetModuleFileNameExW(process, module.hModule, path, MAX_PATH);
                if (!length || length >= MAX_PATH) { error = INJECTION_ERR_MODULES; break; }
                candidate = path;
            }
            if (_wcsicmp(candidate, name) == 0) {
                *base = (unsigned long long)module.modBaseAddr;
                *size = module.modBaseSize;
                error = INJECTION_OK;
                break;
            }
        } while (Module32NextW(snapshot, &module));
        if (error != INJECTION_OK && GetLastError() != ERROR_NO_MORE_FILES) error = INJECTION_ERR_MODULES;
    } else error = INJECTION_ERR_MODULES;
    CloseHandle(snapshot);
    return error;
}

static InjectionError loader_address(HANDLE process, unsigned int pid, LPTHREAD_START_ROUTINE *entry)
{
    HMODULE owner;
    FARPROC loader = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    wchar_t path[MAX_PATH], *name;
    unsigned long long base, offset;
    DWORD size, length;
    InjectionError error;
    if (!loader || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)loader, &owner)) return INJECTION_ERR_MODULES;
    length = GetModuleFileNameW(owner, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return INJECTION_ERR_MODULES;
    name = wcsrchr(path, L'\\');
    error = find_module(process, pid, name ? name + 1 : path, 0, &base, &size);
    if (error != INJECTION_OK) return error;
    offset = (unsigned long long)loader - (unsigned long long)owner;
    if (offset >= size) return INJECTION_ERR_MODULES;
    *entry = (LPTHREAD_START_ROUTINE)(UINT_PTR)(base + offset);
    return INJECTION_OK;
}
