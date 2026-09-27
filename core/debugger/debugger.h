#ifndef DEBUGGER_H
#define DEBUGGER_H

#include "core/process/process.h"
#include "platform/debugger.h"

typedef enum {
    DEBUGGER_OK = 0,
    DEBUGGER_ERR_INVALID_PARAM,
    DEBUGGER_ERR_ATTACH,
    DEBUGGER_ERR_DETACH,
    DEBUGGER_ERR_WAIT,
    DEBUGGER_ERR_CONTINUE,
    DEBUGGER_ERR_NOT_PAUSED,
    DEBUGGER_ERR_READ,
    DEBUGGER_ERR_CONTEXT,
    DEBUGGER_ERR_CAPACITY,
    DEBUGGER_ERR_UNSUPPORTED,
    DEBUGGER_ERR_INTERNAL
} DebuggerError;

typedef PlatformDebugRegisters DebuggerRegisters;
typedef struct {
    int attached, watching, paused, registers_valid, value_valid;
    unsigned long long address;
    unsigned int size, thread_id;
    unsigned char before[8], after[8];
    DebuggerRegisters registers; /* RIP is the next instruction after the write. */
} DebuggerState;
typedef struct Debugger Debugger;

/* One naturally aligned 1/2/4/8-byte value, across all target threads.
   Calls belong to the attaching thread. Target handle borrowed until successful
   detach. Failed setup/cleanup may retain a session for cleanup retry. */
DebuggerError debugger_watch(const Target *target, unsigned long long address,
                             unsigned int size, Debugger **session);
DebuggerError debugger_poll(Debugger *session);
DebuggerError debugger_continue(Debugger *session);
DebuggerError debugger_detach(Debugger **session);
void debugger_get_state(const Debugger *session, DebuggerState *state);
const char *debugger_error_string(DebuggerError error);

#endif
