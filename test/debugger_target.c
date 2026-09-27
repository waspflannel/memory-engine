#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

__declspec(align(8)) static volatile LONG64 counter;
static volatile LONG handled, heartbeat, stopping, peer_write, completed;
static void (*tick)(volatile LONG *);

static DWORD WINAPI peer(void *argument)
{
    (void)argument;
    while (!InterlockedCompareExchange(&stopping, 0, 0)) {
        InterlockedIncrement(&heartbeat);
        if (InterlockedExchange(&peer_write, 0)) {
            tick((volatile LONG *)&counter);
            InterlockedIncrement(&completed);
        }
        Sleep(1);
    }
    return 0;
}

static DWORD WINAPI write_once(void *argument)
{
    (void)argument;
    tick((volatile LONG *)&counter);
    InterlockedIncrement(&completed);
    return 0;
}

int main(void)
{
    /* INC [RCX]; RET, then MOV EAX,[RCX]; MOV [RCX],EAX; RET at +16.
       Known bytes make register/next-RIP assertions independent of optimization. */
    const unsigned char increment[] = { 0xff, 0x01, 0xc3 };
    const unsigned char increment_byte[] = { 0xfe, 0x01, 0xc3 };
    const unsigned char same_value[] = { 0x8b, 0x01, 0x89, 0x01, 0xc3 };
    unsigned char *code = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned char *same_code, *byte_code;
    DWORD previous, peer_tid;
    HANDLE worker;
    void (*store_same)(volatile LONG *);
    void (*tick_byte)(volatile unsigned char *);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (!code) return 1;
    memcpy(code, increment, sizeof(increment));
    memcpy(code + 16, same_value, sizeof(same_value));
    memcpy(code + 32, increment_byte, sizeof(increment_byte));
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &previous) ||
        !FlushInstructionCache(GetCurrentProcess(), code, 4096)) return 2;
    same_code = code + 16;
    memcpy(&tick, &code, sizeof(tick));
    memcpy(&store_same, &same_code, sizeof(store_same));
    byte_code = code + 32;
    memcpy(&tick_byte, &byte_code, sizeof(tick_byte));
    worker = CreateThread(NULL, 0, peer, NULL, 0, &peer_tid);
    if (!worker) return 3;
    printf("%u %llx %llx %llx %llx %u %llx\n", (unsigned int)GetCurrentThreadId(),
           (unsigned long long)(UINT_PTR)code, (unsigned long long)(UINT_PTR)&counter,
           (unsigned long long)(UINT_PTR)&handled, (unsigned long long)(UINT_PTR)&heartbeat,
           (unsigned int)peer_tid, (unsigned long long)(UINT_PTR)&completed);
    fflush(stdout);
    for (;;) {
        DWORD available, got;
        char command;
        if (!PeekNamedPipe(GetStdHandle(STD_INPUT_HANDLE), NULL, 0, NULL, &available, NULL)) break;
        if (!available) { Sleep(1); continue; }
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), &command, 1, &got, NULL) || !got) break;
        if (command == 'q') break;
        if (command == 'i' || command == 's') {
            if (command == 'i') tick((volatile LONG *)&counter);
            else store_same((volatile LONG *)&counter);
            InterlockedIncrement(&completed);
        }
        if (command == '1' || command == '2' || command == '4' || command == '8') {
            tick_byte((volatile unsigned char *)&counter + (command - '1'));
            InterlockedIncrement(&completed);
        }
        if (command == 'p') InterlockedExchange(&peer_write, 1);
        if (command == 'n') {
            HANDLE fresh = CreateThread(NULL, 0, write_once, NULL, 0, NULL);
            if (!fresh) return 4;
            CloseHandle(fresh);
        }
        if (command == 'u') RaiseException(0xe0424243, 0, 0, NULL);
        if (command == 'e' || command == 'b') {
            __try {
                RaiseException(command == 'e' ? 0xe0424242 : EXCEPTION_BREAKPOINT, 0, 0, NULL);
            } __except (GetExceptionCode() == 0xe0424242 || GetExceptionCode() == EXCEPTION_BREAKPOINT ?
                        EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                handled++;
            }
        }
    }
    InterlockedExchange(&stopping, 1);
    if (WaitForSingleObject(worker, 1000) != WAIT_OBJECT_0) return 5;
    CloseHandle(worker);
    VirtualFree(code, 0, MEM_RELEASE);
    return 0;
}
