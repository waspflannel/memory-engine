#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "core/injector/injector.h"
#include "test/test.h"

#define REQUIRE(condition, message) do { \
    int passed = !!(condition); check(passed, message); if (!passed) goto cleanup; \
} while (0)

int main(int argc, char **argv)
{
    PROCESS_INFORMATION child = {0};
    STARTUPINFOW startup = {0};
    wchar_t executable[MAX_PATH], command[MAX_PATH + 32], fixture[MAX_PATH];
    wchar_t name[80], temporary[MAX_PATH], copied[MAX_PATH];
    HANDLE started = NULL, release = NULL, reject = NULL, file = INVALID_HANDLE_VALUE;
    Target target = {0};
    Injection *injection = NULL;
    InjectionError error;
    unsigned long long base = 0;
    int complete = 0;
    DWORD before, after, written;
    ULONGLONG deadline;
    IMAGE_DOS_HEADER dos;
    LARGE_INTEGER offset;
    WORD machine = IMAGE_FILE_MACHINE_I386;
    copied[0] = L'\0';
    if (argc > 1 && strcmp(argv[1], "--target") == 0) { Sleep(INFINITE); return 0; }
    REQUIRE(GetModuleFileNameW(NULL, executable, MAX_PATH), "find test executable");
    swprintf_s(command, MAX_PATH + 32, L"\"%ls\" --target", executable);
    startup.cb = sizeof(startup);
    REQUIRE(CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child), "launch injection target");
    /* Wait for loader initialization without assuming an arbitrary startup delay. */
    deadline = GetTickCount64() + 5000;
    do {
        if (process_attach(child.dwProcessId, &target) == PLATFORM_OK) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    REQUIRE(target.handle, "attach injection target");
    REQUIRE(GetFullPathNameW(L"injector_fixture.dll", MAX_PATH, fixture, NULL), "resolve test DLL");
    swprintf_s(name, 80, L"Local\\MemForgeInjectionStarted%lu", child.dwProcessId);
    started = CreateEventW(NULL, TRUE, FALSE, name);
    swprintf_s(name, 80, L"Local\\MemForgeInjectionRelease%lu", child.dwProcessId);
    release = CreateEventW(NULL, TRUE, FALSE, name);
    REQUIRE(started && release, "create loader marker events");
    REQUIRE(GetTempPathW(MAX_PATH, temporary), "find temporary directory");
    swprintf_s(copied, MAX_PATH, L"%lsmemforge-%lu-\x03bb.dll", temporary, GetCurrentProcessId());
    REQUIRE(CopyFileW(fixture, copied, FALSE), "copy DLL to Unicode path");
    REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &before), "record handle baseline");
    REQUIRE(platform_inject_start(GetCurrentProcessId(), fixture, &injection) == INJECTION_ERR_INVALID && !injection,
            "reject self injection");
    REQUIRE(injector_start(&target, L"missing-memforge-dll.dll", &injection) == INJECTION_ERR_PATH && !injection, "reject missing DLL without leaked session");
    REQUIRE(injector_start(&target, executable, &injection) == INJECTION_ERR_NOT_DLL && !injection, "reject executable rather than DLL");
    REQUIRE(injector_start(&target, copied, &injection) == INJECTION_OK, "start asynchronous Unicode DLL injection");
    REQUIRE(WaitForSingleObject(started, 5000) == WAIT_OBJECT_0, "DLL entrypoint executed in controlled target");
    REQUIRE(injector_poll(injection, &complete, &base) == INJECTION_OK && !complete && !base, "poll does not block pending loader");
    REQUIRE(injector_release(&injection) == INJECTION_ERR_BUSY && injection, "pending loader retains session and remote path");
    SetEvent(release);
    deadline = GetTickCount64() + 5000;
    do {
        error = injector_poll(injection, &complete, &base);
        if (complete || error != INJECTION_OK) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    if (error != INJECTION_OK || !complete || base <= 0xffffffffull) {
        fprintf(stderr, "injection result: error=%d complete=%d base=%llx\n", error, complete, base);
    }
    REQUIRE(error == INJECTION_OK && complete && base > 0xffffffffull, "confirm full-width module base after loading");
    REQUIRE(injector_release(&injection) == INJECTION_OK && !injection, "release completed injection");
    REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &after) && after == before, "success and failure paths preserve handle count");
    swprintf_s(name, 80, L"Local\\MemForgeInjectionReject%lu", child.dwProcessId);
    reject = CreateEventW(NULL, TRUE, FALSE, name);
    REQUIRE(reject, "request test DLL loader rejection");
    REQUIRE(injector_start(&target, fixture, &injection) == INJECTION_OK, "start DLL whose entrypoint rejects loading");
    deadline = GetTickCount64() + 5000;
    do {
        error = injector_poll(injection, &complete, &base);
        if (complete || error != INJECTION_OK) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    REQUIRE(error == INJECTION_ERR_LOAD && complete && !base, "report loader rejection without a fake module base");
    REQUIRE(injector_release(&injection) == INJECTION_OK && !injection, "release rejected load");
    CloseHandle(reject); reject = NULL;
    ResetEvent(started);
    ResetEvent(release);
    REQUIRE(injector_start(&target, fixture, &injection) == INJECTION_OK, "start pending load before target termination");
    REQUIRE(WaitForSingleObject(started, 5000) == WAIT_OBJECT_0, "pending DLL reached entrypoint");
    TerminateProcess(child.hProcess, 0);
    WaitForSingleObject(child.hProcess, 5000);
    REQUIRE(injector_poll(injection, &complete, &base) == INJECTION_ERR_LOAD && complete && !base,
            "target exit reports failure for pending injection");
    REQUIRE(injector_release(&injection) == INJECTION_OK && !injection, "release session after target exit");
    /* Corrupt only the copied file's machine field to cover architecture rejection. */
    file = CreateFileW(copied, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    REQUIRE(file != INVALID_HANDLE_VALUE, "open unloaded test copy");
    REQUIRE(ReadFile(file, &dos, sizeof(dos), &written, NULL) && written == sizeof(dos), "read test copy PE header");
    offset.QuadPart = dos.e_lfanew + sizeof(DWORD);
    REQUIRE(SetFilePointerEx(file, offset, NULL, FILE_BEGIN) && WriteFile(file, &machine, sizeof(machine), &written, NULL), "write wrong DLL architecture");
    CloseHandle(file); file = INVALID_HANDLE_VALUE;
    REQUIRE(injector_start(&target, copied, &injection) == INJECTION_ERR_ARCHITECTURE && !injection, "reject wrong DLL architecture before target access");
cleanup:
    if (release) SetEvent(release);
    if (child.hProcess) { TerminateProcess(child.hProcess, 0); WaitForSingleObject(child.hProcess, 5000); }
    if (injection) injector_release(&injection);
    process_detach(&target);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (started) CloseHandle(started);
    if (release) CloseHandle(release);
    if (reject) CloseHandle(reject);
    if (child.hThread) CloseHandle(child.hThread);
    if (child.hProcess) CloseHandle(child.hProcess);
    if (*copied) DeleteFileW(copied);
    printf("injector tests: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
