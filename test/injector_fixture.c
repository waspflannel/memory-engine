#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    wchar_t name[80];
    HANDLE started, release, reject;
    (void)instance;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    swprintf_s(name, 80, L"Local\\MemForgeInjectionStarted%lu", GetCurrentProcessId());
    started = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (started) { SetEvent(started); CloseHandle(started); }
    /* Test-only loader delay proves pending injection cannot free its argument. */
    swprintf_s(name, 80, L"Local\\MemForgeInjectionRelease%lu", GetCurrentProcessId());
    release = OpenEventW(SYNCHRONIZE, FALSE, name);
    if (release) { WaitForSingleObject(release, 10000); CloseHandle(release); }
    swprintf_s(name, 80, L"Local\\MemForgeInjectionReject%lu", GetCurrentProcessId());
    reject = OpenEventW(SYNCHRONIZE, FALSE, name);
    if (reject) { CloseHandle(reject); return FALSE; }
    return TRUE;
}
