#ifndef DEBUGGER_INTERNAL_H
#define DEBUGGER_INTERNAL_H

#include "core/debugger/debugger.h"

typedef struct DebugThread {
    unsigned int id;
    void *handle;
    int breakin, slot, configured;
    unsigned long long original_dr, original_dr7, original_dr6;
    struct DebugThread *next;
} DebugThread;

struct Debugger {
    Target target;
    DebuggerState state;
    unsigned char baseline[8];
    DebugThread *threads;
    void *process_event_handle;
    PlatformDebugEvent event;
    int event_ready, event_handled;
    int initial_break, pause_requested, stopping;
    unsigned long long hit_mask, breakin_address;
};

DebugThread *debugger_find_thread(Debugger *session, unsigned int id);
void debugger_free_threads(Debugger *session, int close_handles);
DebuggerError debugger_arm_thread(Debugger *session, DebugThread *thread);
DebuggerError debugger_restore_threads(Debugger *session);
DebuggerError debugger_read_value(Debugger *session, unsigned char *value);
DebuggerError debugger_dispatch_event(Debugger *session, int *hold);
DebuggerError debugger_poll_event(Debugger *session, unsigned int timeout);
DebuggerError debugger_continue_event(Debugger *session);

#endif
