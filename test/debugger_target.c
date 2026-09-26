#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static volatile LONG counter;
static volatile LONG handled;
static volatile LONG heartbeat;
static volatile LONG stopping;

static DWORD WINAPI peer(void *argument)
{
    (void)argument;
    while (!InterlockedCompareExchange(&stopping, 0, 0)) {
        InterlockedIncrement(&heartbeat);
        Sleep(1);
    }
    return 0;
}

int main(void)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    /* Native x64: inc dword ptr [rcx]; ret. A known instruction makes RIP and
       re-execution checks independent of compiler prologues and optimization. */
    const unsigned char instruction[] = { 0xff, 0x01, 0xc3 };
    unsigned char *code = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    DWORD previous;
    HANDLE worker;
    void (*tick)(volatile LONG *);
    if (!code) return 1;
    memset(code, 0xc3, 4096);
    memcpy(code, instruction, sizeof(instruction));
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &previous) ||
        !FlushInstructionCache(GetCurrentProcess(), code, 4096)) return 2;
    memcpy(&tick, &code, sizeof(tick));
    worker = CreateThread(NULL, 0, peer, NULL, 0, NULL);
    if (!worker) return 3;
    printf("%u %llx %llx %llx %llx\n", (unsigned int)GetCurrentThreadId(),
           (unsigned long long)(UINT_PTR)code,
           (unsigned long long)(UINT_PTR)&counter,
           (unsigned long long)(UINT_PTR)&handled,
           (unsigned long long)(UINT_PTR)&heartbeat);
    fflush(stdout);
    for (;;) {
        DWORD available, got;
        char command;
        tick(&counter);
        if (!PeekNamedPipe(GetStdHandle(STD_INPUT_HANDLE), NULL, 0, NULL,
                           &available, NULL)) break;
        if (available) {
            if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), &command, 1, &got, NULL) || !got)
                break;
            if (command == 'q') break;
            if (command == 'u') RaiseException(0xe0424243, 0, 0, NULL);
            if (command == 'e' || command == 'b') {
                __try {
                    RaiseException(command == 'e' ? 0xe0424242 : EXCEPTION_BREAKPOINT, 0, 0, NULL);
                } __except (GetExceptionCode() == 0xe0424242 ||
                            GetExceptionCode() == EXCEPTION_BREAKPOINT ?
                            EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                    handled++;
                }
            }
        }
        Sleep(1);
    }
    InterlockedExchange(&stopping, 1);
    if (WaitForSingleObject(worker, 1000) != WAIT_OBJECT_0) return 4;
    CloseHandle(worker);
    VirtualFree(code, 0, MEM_RELEASE);
    return 0;
}
