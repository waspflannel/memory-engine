#ifndef PLATFORM_DEBUGGER_H
#define PLATFORM_DEBUGGER_H

#include "platform/platform.h"

#define PLATFORM_DEBUG_BREAKPOINT 0x80000003u
#define PLATFORM_DEBUG_SINGLE_STEP 0x80000004u

typedef struct {
    unsigned long long rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    unsigned long long r8, r9, r10, r11, r12, r13, r14, r15, rip;
    unsigned int eflags;
} PlatformDebugRegisters;

typedef struct {
    PlatformDebugRegisters registers;
    unsigned long long dr[4], dr6, dr7;
} PlatformDebugContext;

typedef enum {
    PLATFORM_DEBUG_OTHER, PLATFORM_DEBUG_CREATE_THREAD, PLATFORM_DEBUG_EXIT_THREAD,
    PLATFORM_DEBUG_EXIT_PROCESS, PLATFORM_DEBUG_EXCEPTION
} PlatformDebugEventKind;

typedef struct {
    PlatformDebugEventKind kind;
    unsigned int process_id, thread_id;
    /* Windows closes event handles on exit continuation. Close remaining live
       handles only after a successful DebugActiveProcessStop. */
    void *thread_handle, *process_handle;
    unsigned long long thread_start;
    unsigned int exception_code;
    unsigned long long exception_address;
    int first_chance;
} PlatformDebugEvent;

PlatformError platform_debug_supported(void *process, unsigned int pid, int *supported);
PlatformError platform_debug_breakin_address(unsigned int pid, unsigned long long *address);
PlatformError platform_debug_attach(unsigned int pid);
PlatformError platform_debug_keep_target_alive(void);
PlatformError platform_debug_stop(unsigned int pid);
PlatformError platform_debug_break(void *process);
PlatformError platform_debug_wait(unsigned int timeout_ms, PlatformDebugEvent *event, int *available);
PlatformError platform_debug_continue(const PlatformDebugEvent *event, int handled);
PlatformError platform_debug_get_context(void *thread, PlatformDebugContext *context);
/* Changes only RIP/EFLAGS and debug registers; all other context stays intact. */
PlatformError platform_debug_set_context(void *thread, const PlatformDebugContext *context);
PlatformError platform_debug_suspend(void *thread);
PlatformError platform_debug_resume(void *thread);
/* protection starts at zero and retains the original protection across retries.
   Failure can follow a successful write: callers must retain restoration state. */
PlatformError platform_debug_patch(void *process, unsigned long long address,
                                  unsigned char byte, unsigned int *protection);

#endif
