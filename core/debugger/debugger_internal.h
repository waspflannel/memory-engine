#ifndef DEBUGGER_INTERNAL_H
#define DEBUGGER_INTERNAL_H

#include "core/debugger/debugger.h"

#define TRAP_FLAG 0x100u
#define RESUME_FLAG 0x10000u
#define SINGLE_STEP_STATUS (1ull << 14)

typedef struct DebugThread {
    unsigned int id;
    void *handle;
    int suspended;
    int breakin;
    struct DebugThread *next;
} DebugThread;

typedef struct {
    unsigned char original_byte;
    unsigned int protection;
    unsigned long long original_dr, original_dr7, original_dr6;
    int repair_required;
} BreakpointRestore;

struct Debugger {
    Target target;
    DebuggerState state;
    DebugThread *threads;
    void *process_event_handle;
    BreakpointRestore restore[DEBUGGER_MAX_BREAKPOINTS];
    PlatformDebugEvent event;
    int event_ready, event_handled;
    int initial_break, pause_requested;
    int pending_software;
    unsigned int step_thread, step_flags;
    int step_flags_set, step_event;
    unsigned long long hardware_hit_mask;
    unsigned long long breakin_address;
    int step_hardware_resumed;
};

/* Shared implementation details; callers use debugger.h. */
DebugThread *debugger_find_thread(Debugger *session, unsigned int id);
void debugger_free_threads(Debugger *session, int close_handles);
DebuggerError debugger_resume_threads(Debugger *session);
DebuggerError debugger_finish_step(Debugger *session, int rearm);
DebuggerError debugger_start_step(Debugger *session);
DebuggerError debugger_dispatch_event(Debugger *session, int *hold);
DebuggerError debugger_poll_event(Debugger *session, unsigned int timeout);
DebuggerError debugger_continue_event(Debugger *session);

#endif
