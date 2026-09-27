#include <stdlib.h>
#include <string.h>

#include "core/debugger/debugger_internal.h"

DebuggerError debugger_dispatch_event(Debugger *session, int *hold)
{
    PlatformDebugEvent *event = &session->event;
    *hold = 0;
    switch (event->kind) {
    case PLATFORM_DEBUG_CREATE_THREAD: {
        if (event->process_handle) {
            session->process_event_handle = event->process_handle;
            event->process_handle = NULL;
        }
        DebugThread *thread = debugger_find_thread(session, event->thread_id);
        if (!thread) {
            if (!event->thread_handle) return DEBUGGER_ERR_CONTEXT;
            thread = calloc(1, sizeof(*thread));
            if (!thread) return DEBUGGER_ERR_INTERNAL;
            thread->id = event->thread_id;
            thread->slot = -1;
            thread->breakin = event->thread_start == session->breakin_address;
            thread->handle = event->thread_handle;
            event->thread_handle = NULL;
            thread->next = session->threads;
            session->threads = thread;
        }
        return session->state.watching && !session->stopping
               ? debugger_arm_thread(session, thread) : DEBUGGER_OK;
    }
    case PLATFORM_DEBUG_EXIT_THREAD: {
        DebugThread **link = &session->threads;
        while (*link && (*link)->id != event->thread_id) link = &(*link)->next;
        if (*link) {
            DebugThread *thread = *link;
            *link = thread->next;
            free(thread); /* Windows closes the event handle on continuation. */
        }
        return DEBUGGER_OK;
    }
    case PLATFORM_DEBUG_EXCEPTION:
        break;
    default:
        return DEBUGGER_OK;
    }

    DebugThread *thread = debugger_find_thread(session, event->thread_id);
    if (event->exception_code == PLATFORM_DEBUG_BREAKPOINT && thread && thread->breakin &&
        (session->initial_break || session->pause_requested)) {
        session->event_handled = 1;
        if (session->stopping) {
            *hold = 1;
        } else {
            for (DebugThread *current = session->threads; current; current = current->next) {
                DebuggerError error = debugger_arm_thread(session, current);
                if (error != DEBUGGER_OK) return error;
            }
            DebuggerError error = debugger_read_value(session, session->state.after);
            if (error != DEBUGGER_OK) return error;
            memcpy(session->state.before, session->state.after, session->state.size);
            memcpy(session->baseline, session->state.after, session->state.size);
            session->state.value_valid = 1;
            session->state.watching = 1;
        }
        session->initial_break = 0;
        session->pause_requested = 0;
        return DEBUGGER_OK;
    }

    if (event->exception_code == PLATFORM_DEBUG_SINGLE_STEP && thread && thread->configured) {
        PlatformDebugContext context;
        if (platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        unsigned long long owned = 1ull << thread->slot;
        if (!(context.dr6 & owned)) return DEBUGGER_OK;
        session->hit_mask = owned;
        /* Pass simultaneous foreign debug causes (other slots, BD, BS, BT) onward. */
        session->event_handled = !(context.dr6 & ((15ull & ~owned) | (7ull << 13)));
        if (session->stopping) {
            *hold = 1;
            return DEBUGGER_OK;
        }
        unsigned char value[8];
        session->state.value_valid = 0;
        DebuggerError error = debugger_read_value(session, value);
        if (error != DEBUGGER_OK) return error;
        session->state.value_valid = 1;
        if (memcmp(value, session->baseline, session->state.size)) {
            memcpy(session->state.before, session->baseline, session->state.size);
            memcpy(session->state.after, value, session->state.size);
            session->state.registers = context.registers;
            session->state.registers_valid = 1;
            *hold = 1;
        }
    }
    return DEBUGGER_OK;
}

DebuggerError debugger_poll_event(Debugger *session, unsigned int timeout)
{
    int available = 0;
    PlatformError waited = platform_debug_wait(timeout, &session->event, &available);
    if (!available) return waited == PLATFORM_OK ? DEBUGGER_OK : DEBUGGER_ERR_WAIT;
    session->state.paused = 1;
    session->state.registers_valid = 0;
    session->state.thread_id = session->event.thread_id;
    session->event_ready = 0;
    session->event_handled = session->event.kind != PLATFORM_DEBUG_EXCEPTION;
    session->hit_mask = 0;
    if (waited != PLATFORM_OK) return DEBUGGER_ERR_WAIT;
    int hold = 0;
    DebuggerError error = debugger_dispatch_event(session, &hold);
    if (error != DEBUGGER_OK) return error;
    session->event_ready = 1;
    return hold ? DEBUGGER_OK : debugger_continue_event(session);
}

DebuggerError debugger_continue_event(Debugger *session)
{
    if (session->hit_mask) {
        DebugThread *thread = debugger_find_thread(session, session->event.thread_id);
        PlatformDebugContext context;
        if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        context.dr6 &= ~session->hit_mask;
        if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    }
    if (platform_debug_continue(&session->event, session->event_handled) != PLATFORM_OK) return DEBUGGER_ERR_CONTINUE;
    session->state.paused = 0;
    session->state.registers_valid = 0;
    session->hit_mask = 0;
    if (session->event.kind == PLATFORM_DEBUG_EXIT_PROCESS) {
        session->state = (DebuggerState){0};
        debugger_free_threads(session, 0);
        session->process_event_handle = NULL;
    }
    session->event = (PlatformDebugEvent){0};
    return DEBUGGER_OK;
}

DebugThread *debugger_find_thread(Debugger *session, unsigned int id)
{
    for (DebugThread *thread = session->threads; thread; thread = thread->next) {
        if (thread->id == id) return thread;
    }
    return NULL;
}

void debugger_free_threads(Debugger *session, int close_handles)
{
    while (session->threads) {
        DebugThread *thread = session->threads;
        session->threads = thread->next;
        if (close_handles) platform_close_handle(thread->handle);
        free(thread);
    }
}
