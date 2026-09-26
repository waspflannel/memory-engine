#include <stdlib.h>

#include "core/debugger/debugger_internal.h"

DebuggerError debugger_attach(const Target *target, Debugger **session)
{
    if (!target || !target->handle || !session || *session) return DEBUGGER_ERR_INVALID_PARAM;
    int supported = 0;
    if (platform_debug_supported(target->handle, target->pid, &supported) != PLATFORM_OK) {
        return DEBUGGER_ERR_ATTACH;
    }
    if (!supported) return DEBUGGER_ERR_UNSUPPORTED;
    Debugger *created = calloc(1, sizeof(*created));
    if (!created) return DEBUGGER_ERR_INTERNAL;
    created->target = *target;
    created->pending_software = -1;
    created->initial_break = 1;
    if (platform_debug_breakin_address(target->pid, &created->breakin_address) != PLATFORM_OK) {
        free(created);
        return DEBUGGER_ERR_ATTACH;
    }
    if (platform_debug_attach(target->pid) != PLATFORM_OK) {
        free(created);
        return DEBUGGER_ERR_ATTACH;
    }
    created->state.attached = 1;
    if (platform_debug_keep_target_alive() != PLATFORM_OK) {
        if (platform_debug_stop(target->pid) == PLATFORM_OK) free(created);
        else *session = created; /* Keep a failed rollback reachable for detach. */
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

DebuggerError debugger_pause(Debugger *session)
{
    if (!session || !session->state.attached) return DEBUGGER_ERR_INVALID_PARAM;
    if (session->state.paused || session->pause_requested || session->initial_break) return DEBUGGER_OK;
    if (platform_debug_break(session->target.handle) != PLATFORM_OK) return DEBUGGER_ERR_WAIT;
    session->pause_requested = 1;
    return DEBUGGER_OK;
}

DebuggerError debugger_continue(Debugger *session)
{
    if (!session || !session->state.attached) return DEBUGGER_ERR_INVALID_PARAM;
    if (!session->state.paused) return DEBUGGER_ERR_NOT_PAUSED;
    if (!session->event_ready) {
        int hold = 0;
        DebuggerError error = debugger_dispatch_event(session, &hold);
        if (error != DEBUGGER_OK) return error;
        session->event_ready = 1;
    }
    for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
        if (session->state.breakpoints[i].active && session->restore[i].repair_required) {
            return DEBUGGER_ERR_PATCH;
        }
    }
    if (session->pending_software >= 0 && !session->step_flags_set) {
        DebuggerError error = debugger_start_step(session);
        if (error != DEBUGGER_OK) return error;
    }
    if (session->hardware_hit_mask) {
        DebugThread *thread = debugger_find_thread(session, session->event.thread_id);
        PlatformDebugContext context;
        if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) {
            return DEBUGGER_ERR_CONTEXT;
        }
        context.registers.eflags |= RESUME_FLAG;
        context.dr6 &= ~session->hardware_hit_mask;
        if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        if (session->pending_software >= 0 && session->event.thread_id == session->step_thread) {
            session->step_hardware_resumed = 1;
        }
    }
    return debugger_continue_event(session);
}

void debugger_get_state(const Debugger *session, DebuggerState *state)
{
    if (!state) return;
    *state = session ? session->state : (DebuggerState){0};
}

DebuggerError debugger_detach(Debugger **session)
{
    if (!session) return DEBUGGER_ERR_INVALID_PARAM;
    Debugger *current = *session;
    if (!current) return DEBUGGER_OK;
    /* Consume an already queued exit before requesting a break on a dead target.
       Bound the drain even for a target with many thread/module events. */
    for (unsigned int attempt = 0; attempt < 64 && current->state.attached && !current->state.paused; attempt++) {
        DebuggerError error = debugger_poll_event(current, 0);
        if (error != DEBUGGER_OK) return error;
    }
    if (current->state.attached && !current->state.paused) {
        DebuggerError error = debugger_pause(current);
        if (error != DEBUGGER_OK) return error;
        /* Bounded drain: a failed stop leaves the borrowed target and session intact. */
        for (unsigned int attempt = 0; attempt < 500 && current->state.attached && !current->state.paused; attempt++) {
            error = debugger_poll_event(current, 10);
            if (error != DEBUGGER_OK) return error;
        }
        if (current->state.attached && !current->state.paused) return DEBUGGER_ERR_DETACH;
    }
    if (current->state.attached) {
        if (!current->event_ready) {
            int hold = 0;
            DebuggerError error = debugger_dispatch_event(current, &hold);
            if (error != DEBUGGER_OK) return error;
            current->event_ready = 1;
        }
        for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
            if (!current->state.breakpoints[i].active) continue;
            DebuggerError error = debugger_remove(current, i);
            if (error != DEBUGGER_OK) return error;
        }
        DebuggerError error = debugger_resume_threads(current);
        if (error != DEBUGGER_OK) return error;
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

const char *debugger_error_string(DebuggerError error)
{
    switch (error) {
    case DEBUGGER_OK: return "Success";
    case DEBUGGER_ERR_INVALID_PARAM: return "Invalid debugger argument or session state";
    case DEBUGGER_ERR_ATTACH: return "Debugger attach failed";
    case DEBUGGER_ERR_DETACH: return "Debugger detach failed; session retained for retry";
    case DEBUGGER_ERR_WAIT: return "Debugger event wait or pause request failed";
    case DEBUGGER_ERR_CONTINUE: return "Debug event continuation failed";
    case DEBUGGER_ERR_NOT_PAUSED: return "Pause the debugger before editing breakpoints";
    case DEBUGGER_ERR_PATCH: return "Breakpoint memory patch or restoration failed";
    case DEBUGGER_ERR_CONTEXT: return "Thread context or suspension operation failed";
    case DEBUGGER_ERR_CAPACITY: return "No breakpoint slots available";
    case DEBUGGER_ERR_NOT_FOUND: return "Thread or breakpoint not found";
    case DEBUGGER_ERR_UNSUPPORTED: return "Requires native x64 target and an instruction without an existing INT3";
    default: return "Internal debugger error";
    }
}
