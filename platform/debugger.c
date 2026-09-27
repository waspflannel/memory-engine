#include <windows.h>
#include <tlhelp32.h>

#include "platform/debugger.h"

PlatformError platform_debug_supported(void *process, unsigned int pid, int *supported)
{
    BOOL wow64 = FALSE;
    SYSTEM_INFO info;
    GetNativeSystemInfo(&info);
    if (!IsWow64Process(process, &wow64)) return PLATFORM_ERR_QUERY_FAILED;
    *supported = !wow64 && info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 &&
                 pid != GetCurrentProcessId();
    return PLATFORM_OK;
}

PlatformError platform_debug_breakin_address(unsigned int pid, unsigned long long *address)
{
    HMODULE local = GetModuleHandleW(L"ntdll.dll");
    FARPROC entry = local ? GetProcAddress(local, "DbgUiRemoteBreakin") : NULL;
    if (!entry) return PLATFORM_ERR_MODULE_FAILED;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return PLATFORM_ERR_SNAPSHOT_FAILED;
    MODULEENTRY32W module = {0};
    module.dwSize = sizeof(module);
    BOOL found = Module32FirstW(snapshot, &module);
    PlatformError result = PLATFORM_ERR_MODULE_FAILED;
    while (found) {
        if (_wcsicmp(module.szModule, L"ntdll.dll") == 0) {
            *address = (unsigned long long)module.modBaseAddr +
                       ((unsigned long long)entry - (unsigned long long)local);
            result = PLATFORM_OK;
            break;
        }
        found = Module32NextW(snapshot, &module);
    }
    CloseHandle(snapshot);
    return result;
}

PlatformError platform_debug_attach(unsigned int pid)
{
    return DebugActiveProcess(pid) ? PLATFORM_OK : PLATFORM_ERR_ACCESS_DENIED;
}

PlatformError platform_debug_keep_target_alive(void)
{
    return DebugSetProcessKillOnExit(FALSE) ? PLATFORM_OK : PLATFORM_ERR_INTERNAL;
}

PlatformError platform_debug_stop(unsigned int pid)
{
    return DebugActiveProcessStop(pid) ? PLATFORM_OK : PLATFORM_ERR_INTERNAL;
}

PlatformError platform_debug_break(void *process)
{
    DWORD pid = GetProcessId(process);
    if (!pid) return PLATFORM_ERR_QUERY_FAILED;
    HANDLE debug_process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                      FALSE, pid);
    if (!debug_process) return PLATFORM_ERR_ACCESS_DENIED;
    BOOL result = DebugBreakProcess(debug_process);
    CloseHandle(debug_process);
    return result ? PLATFORM_OK : PLATFORM_ERR_INTERNAL;
}

PlatformError platform_debug_wait(unsigned int timeout_ms, PlatformDebugEvent *event, int *available)
{
    DEBUG_EVENT native = {0};
    *available = 0;
    if (!WaitForDebugEvent(&native, timeout_ms)) {
        DWORD error = GetLastError();
        return error == ERROR_SEM_TIMEOUT ? PLATFORM_OK : PLATFORM_ERR_INTERNAL;
    }
    *available = 1;
    *event = (PlatformDebugEvent){0};
    event->process_id = native.dwProcessId;
    event->thread_id = native.dwThreadId;
    switch (native.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT:
        if (native.u.CreateProcessInfo.hFile) CloseHandle(native.u.CreateProcessInfo.hFile);
        event->kind = PLATFORM_DEBUG_CREATE_THREAD;
        event->thread_start = (unsigned long long)native.u.CreateProcessInfo.lpStartAddress;
        event->thread_handle = native.u.CreateProcessInfo.hThread;
        event->process_handle = native.u.CreateProcessInfo.hProcess;
        break;
    case CREATE_THREAD_DEBUG_EVENT:
        event->kind = PLATFORM_DEBUG_CREATE_THREAD;
        event->thread_start = (unsigned long long)native.u.CreateThread.lpStartAddress;
        event->thread_handle = native.u.CreateThread.hThread;
        break;
    case EXIT_THREAD_DEBUG_EVENT:
        event->kind = PLATFORM_DEBUG_EXIT_THREAD;
        break;
    case EXIT_PROCESS_DEBUG_EVENT:
        event->kind = PLATFORM_DEBUG_EXIT_PROCESS;
        break;
    case LOAD_DLL_DEBUG_EVENT:
        if (native.u.LoadDll.hFile) CloseHandle(native.u.LoadDll.hFile);
        break;
    case EXCEPTION_DEBUG_EVENT:
        event->kind = PLATFORM_DEBUG_EXCEPTION;
        event->exception_code = native.u.Exception.ExceptionRecord.ExceptionCode;
        break;
    default:
        break;
    }
    return PLATFORM_OK;
}

PlatformError platform_debug_continue(const PlatformDebugEvent *event, int handled)
{
    return ContinueDebugEvent(event->process_id, event->thread_id,
                             handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED)
           ? PLATFORM_OK : PLATFORM_ERR_INTERNAL;
}

PlatformError platform_debug_get_context(void *thread, PlatformDebugContext *context)
{
    CONTEXT native = {0};
    native.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &native)) return PLATFORM_ERR_QUERY_FAILED;
    *context = (PlatformDebugContext){0};
    context->registers = (PlatformDebugRegisters){
        native.Rax, native.Rbx, native.Rcx, native.Rdx, native.Rsi, native.Rdi, native.Rbp, native.Rsp,
        native.R8, native.R9, native.R10, native.R11, native.R12, native.R13, native.R14, native.R15,
        native.Rip, native.EFlags
    };
    context->dr[0] = native.Dr0;
    context->dr[1] = native.Dr1;
    context->dr[2] = native.Dr2;
    context->dr[3] = native.Dr3;
    context->dr6 = native.Dr6;
    context->dr7 = native.Dr7;
    return PLATFORM_OK;
}

PlatformError platform_debug_set_context(void *thread, const PlatformDebugContext *context)
{
    CONTEXT native = {0};
    native.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    native.Dr0 = context->dr[0];
    native.Dr1 = context->dr[1];
    native.Dr2 = context->dr[2];
    native.Dr3 = context->dr[3];
    native.Dr6 = context->dr6;
    native.Dr7 = context->dr7;
    return SetThreadContext(thread, &native) ? PLATFORM_OK : PLATFORM_ERR_QUERY_FAILED;
}
