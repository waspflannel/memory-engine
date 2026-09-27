#include <stdlib.h>

#include "core/debugger/debugger_internal.h"

DebuggerError debugger_watch(const Target *target, unsigned long long address,
                             unsigned int size, Debugger **session)
{
    if (!target || !target->handle || !session || *session || !address ||
        (size != 1 && size != 2 && size != 4 && size != 8) || address % size) {
        return DEBUGGER_ERR_INVALID_PARAM;
    }
    int supported = 0;
    if (platform_debug_supported(target->handle, target->pid, &supported) != PLATFORM_OK) return DEBUGGER_ERR_ATTACH;
    if (!supported) return DEBUGGER_ERR_UNSUPPORTED;
    Debugger *created = calloc(1, sizeof(*created));
    if (!created) return DEBUGGER_ERR_INTERNAL;
    created->target = *target;
    created->initial_break = 1;
    created->state.address = address;
    created->state.size = size;
    DebuggerError error = debugger_read_value(created, created->baseline);
    if (error != DEBUGGER_OK) {
        free(created);
        return error;
    }
    if (platform_debug_breakin_address(target->pid, &created->breakin_address) != PLATFORM_OK ||
        platform_debug_attach(target->pid) != PLATFORM_OK) {
        free(created);
        return DEBUGGER_ERR_ATTACH;
    }
    created->state.attached = 1;
    if (platform_debug_keep_target_alive() != PLATFORM_OK) {
        if (platform_debug_stop(target->pid) == PLATFORM_OK) free(created);
        else *session = created;
        return DEBUGGER_ERR_ATTACH;
    }
    *session = created;
    return DEBUGGER_OK;
}

DebuggerError debugger_poll(Debugger *session)
{
    if (!session) return DEBUGGER_ERR_INVALID_PARAM;
    if (!session->state.attached || session->state.paused) return DEBUGGER_OK;
    return debugger_poll_event(session, 0);
}

DebuggerError debugger_continue(Debugger *session)
{
    if (!session || !session->state.attached || session->stopping) return DEBUGGER_ERR_INVALID_PARAM;
    if (!session->state.paused) return DEBUGGER_ERR_NOT_PAUSED;
    if (!session->event_ready) {
        int hold = 0;
        DebuggerError error = debugger_dispatch_event(session, &hold);
        if (error != DEBUGGER_OK) return error;
        session->event_ready = 1;
    }
    /* Memory may have been edited through another panel while paused. */
    DebuggerError error = debugger_read_value(session, session->baseline);
    if (error != DEBUGGER_OK) return error;
    return debugger_continue_event(session);
}

DebuggerError debugger_detach(Debugger **session)
{
    if (!session) return DEBUGGER_ERR_INVALID_PARAM;
    Debugger *current = *session;
    if (!current) return DEBUGGER_OK;
    current->stopping = 1;
    /* Consume a queued process exit before requesting a break on a dead target. */
    for (unsigned int attempt = 0; attempt < 64 && current->state.attached && !current->state.paused; attempt++) {
        DebuggerError error = debugger_poll_event(current, 0);
        if (error != DEBUGGER_OK) return error;
    }
    if (current->state.attached && !current->state.paused) {
        if (!current->pause_requested && !current->initial_break) {
            if (platform_debug_break(current->target.handle) != PLATFORM_OK) return DEBUGGER_ERR_WAIT;
            current->pause_requested = 1;
        }
        for (unsigned int attempt = 0; attempt < 500 && current->state.attached && !current->state.paused; attempt++) {
            DebuggerError error = debugger_poll_event(current, 10);
            if (error != DEBUGGER_OK) return error;
        }
        if (current->state.attached && !current->state.paused) return DEBUGGER_ERR_DETACH;
    }
    if (current->state.attached) {
        if (!current->event_ready && current->event.kind == PLATFORM_DEBUG_CREATE_THREAD) {
            int hold = 0;
            DebuggerError error = debugger_dispatch_event(current, &hold);
            if (error != DEBUGGER_OK) return error;
        }
        /* Never retry a failed arm while stopping: restore every recorded slot. */
        DebuggerError error = debugger_restore_threads(current);
        if (error != DEBUGGER_OK) return error;
        current->state.watching = 0;
        error = debugger_continue_event(current);
        if (error != DEBUGGER_OK) return error;
        if (platform_debug_stop(current->target.pid) != PLATFORM_OK) return DEBUGGER_ERR_DETACH;
    }
    debugger_free_threads(current, 1);
    if (current->process_event_handle) platform_close_handle(current->process_event_handle);
    free(current);
    *session = NULL;
    return DEBUGGER_OK;
}

void debugger_get_state(const Debugger *session, DebuggerState *state)
{
    if (!state) return;
    *state = session ? session->state : (DebuggerState){0};
}

const char *debugger_error_string(DebuggerError error)
{
    switch (error) {
    case DEBUGGER_OK: return "Success";
    case DEBUGGER_ERR_INVALID_PARAM: return "Watch one aligned 1, 2, 4 or 8-byte value in a valid session";
    case DEBUGGER_ERR_ATTACH: return "Watch attach failed";
    case DEBUGGER_ERR_DETACH: return "Watch detach failed; session retained for retry";
    case DEBUGGER_ERR_WAIT: return "Debug event wait or stop request failed";
    case DEBUGGER_ERR_CONTINUE: return "Debug event continuation failed";
    case DEBUGGER_ERR_NOT_PAUSED: return "The watched process is not paused";
    case DEBUGGER_ERR_READ: return "Cannot read the complete watched value";
    case DEBUGGER_ERR_CONTEXT: return "Cannot read or update a target thread's watch registers";
    case DEBUGGER_ERR_CAPACITY: return "A target thread has no free hardware watch slot";
    case DEBUGGER_ERR_UNSUPPORTED: return "Watching requires another native x64 process";
    default: return "Internal watch error";
    }
}
