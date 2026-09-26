#ifndef DEBUGGER_H
#define DEBUGGER_H

#include "core/process/process.h"
#include "platform/debugger.h"

#define DEBUGGER_MAX_BREAKPOINTS 32

typedef enum {
    DEBUGGER_OK = 0,
    DEBUGGER_ERR_INVALID_PARAM,
    DEBUGGER_ERR_ATTACH,
    DEBUGGER_ERR_DETACH,
    DEBUGGER_ERR_WAIT,
    DEBUGGER_ERR_CONTINUE,
    DEBUGGER_ERR_NOT_PAUSED,
    DEBUGGER_ERR_PATCH,
    DEBUGGER_ERR_CONTEXT,
    DEBUGGER_ERR_CAPACITY,
    DEBUGGER_ERR_NOT_FOUND,
    DEBUGGER_ERR_UNSUPPORTED,
    DEBUGGER_ERR_INTERNAL
} DebuggerError;

typedef PlatformDebugRegisters DebuggerRegisters;

typedef enum { DEBUGGER_SOFTWARE, DEBUGGER_HARDWARE } DebuggerBreakpointKind;

typedef struct {
    int active;
    DebuggerBreakpointKind kind;
    unsigned long long address;
    unsigned int thread_id; /* Hardware execution breakpoints are per-thread. */
    unsigned int slot;
} DebuggerBreakpoint;

typedef struct {
    int attached;
    int paused;
    int registers_valid;
    unsigned int thread_id;
    unsigned int exception_code;
    DebuggerRegisters registers;
    DebuggerBreakpoint breakpoints[DEBUGGER_MAX_BREAKPOINTS];
} DebuggerState;

typedef struct Debugger Debugger;

/* Calls belong to the attaching thread. The target handle is borrowed until
   successful detach. Failed detach leaves the session available for retry. */
DebuggerError debugger_attach(const Target *target, Debugger **session);
DebuggerError debugger_poll(Debugger *session);
DebuggerError debugger_pause(Debugger *session);
DebuggerError debugger_continue(Debugger *session);
DebuggerError debugger_add_software(Debugger *session, unsigned long long address, unsigned int *index);
DebuggerError debugger_add_hardware(Debugger *session, unsigned int thread_id,
                                    unsigned long long address, unsigned int *index);
DebuggerError debugger_remove(Debugger *session, unsigned int index);
void debugger_get_state(const Debugger *session, DebuggerState *state);
DebuggerError debugger_detach(Debugger **session);
const char *debugger_error_string(DebuggerError error);

#endif
