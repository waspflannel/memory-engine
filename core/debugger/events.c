#include <stdlib.h>

#include "core/debugger/debugger_internal.h"

static DebuggerError capture_registers(Debugger *session);

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
            thread->breakin = event->thread_start == session->breakin_address;
            thread->handle = event->thread_handle;
            event->thread_handle = NULL;
            thread->next = session->threads;
            session->threads = thread;
        }
        if (session->step_flags_set && thread->id != session->step_thread && !thread->breakin && !thread->suspended) {
            if (platform_debug_suspend(thread->handle) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
            thread->suspended = 1;
        }
        return DEBUGGER_OK;
    }
    case PLATFORM_DEBUG_EXIT_THREAD: {
        DebugThread **link = &session->threads;
        while (*link && (*link)->id != event->thread_id) link = &(*link)->next;
        if (*link) {
            DebugThread *thread = *link;
            *link = thread->next;
            free(thread);
        }
        for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
            DebuggerBreakpoint *breakpoint = &session->state.breakpoints[i];
            if (breakpoint->active && breakpoint->kind == DEBUGGER_HARDWARE && breakpoint->thread_id == event->thread_id) {
                *breakpoint = (DebuggerBreakpoint){0};
            }
        }
        if (session->pending_software >= 0 && session->step_thread == event->thread_id) return debugger_finish_step(session, 1);
        return DEBUGGER_OK;
    }
    case PLATFORM_DEBUG_EXIT_PROCESS:
        return DEBUGGER_OK;
    case PLATFORM_DEBUG_EXCEPTION:
        break;
    default:
        return DEBUGGER_OK;
    }

    DebugThread *thread = debugger_find_thread(session, event->thread_id);
    PlatformDebugContext context;
    if (event->exception_code == PLATFORM_DEBUG_BREAKPOINT) {
        for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
            DebuggerBreakpoint *breakpoint = &session->state.breakpoints[i];
            if (!breakpoint->active || breakpoint->kind != DEBUGGER_SOFTWARE ||
                breakpoint->address != event->exception_address) continue;
            if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
            if (session->pending_software >= 0 && session->step_thread != event->thread_id) {
                /* Another thread may already have queued an INT3 before all threads
                   stopped. It stays suspended until rearm, then retries the INT3. */
                context.registers.rip = breakpoint->address;
                if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
                session->event_handled = 1;
                return DEBUGGER_OK;
            }
            BreakpointRestore *restore = &session->restore[i];
            if (platform_debug_patch(session->target.handle, breakpoint->address, restore->original_byte,
                                     &restore->protection) != PLATFORM_OK) return DEBUGGER_ERR_PATCH;
            context.registers.rip = breakpoint->address;
            if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
            session->pending_software = (int)i;
            session->step_thread = event->thread_id;
            session->step_flags = context.registers.eflags & (TRAP_FLAG | RESUME_FLAG);
            session->event_handled = 1;
            *hold = 1;
            return capture_registers(session);
        }
        if ((session->initial_break || session->pause_requested) && thread && thread->breakin) {
            session->event_handled = 1;
            *hold = 1;
            DebuggerError error = capture_registers(session);
            if (error == DEBUGGER_OK) {
                session->initial_break = 0;
                session->pause_requested = 0;
            }
            return error;
        }
    }

    if (event->exception_code == PLATFORM_DEBUG_SINGLE_STEP) {
        if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        unsigned long long triggered_slots = context.dr6 & 15ull;
        /* Windows can report zero DR6 in the captured context. Execution slots
           still identify their fault by the instruction pointer and enabled DR7. */
        if (!triggered_slots) {
            for (unsigned int slot = 0; slot < 4; slot++) {
                if ((context.dr7 & (3ull << (slot * 2))) && context.dr[slot] == context.registers.rip &&
                    !(context.dr7 & (15ull << (16 + slot * 4)))) triggered_slots |= 1ull << slot;
            }
        }
        int before_instruction = session->pending_software >= 0 && triggered_slots &&
            context.registers.rip == session->state.breakpoints[session->pending_software].address &&
            !session->step_hardware_resumed;
        int owned_step = session->step_flags_set && event->thread_id == session->step_thread &&
                         ((context.dr6 & SINGLE_STEP_STATUS) != 0 || session->step_event || !before_instruction);
        int foreign_step = (context.dr6 & SINGLE_STEP_STATUS) != 0;
        if (owned_step) {
            session->step_event = 1;
            foreign_step = (session->step_flags & TRAP_FLAG) != 0;
            DebuggerError error = debugger_finish_step(session, 1);
            if (error != DEBUGGER_OK) return error;
            session->event_handled = !foreign_step;
        }
        unsigned long long owned_mask = 0;
        for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
            DebuggerBreakpoint *breakpoint = &session->state.breakpoints[i];
            if (breakpoint->active && breakpoint->kind == DEBUGGER_HARDWARE && breakpoint->thread_id == event->thread_id) {
                owned_mask |= 1ull << breakpoint->slot;
            }
        }
        session->hardware_hit_mask = triggered_slots & owned_mask;
        unsigned long long foreign_mask = (triggered_slots & ~owned_mask) | (context.dr6 & ((1ull << 13) | (1ull << 15)));
        if (foreign_mask) session->event_handled = 0;
        if (session->hardware_hit_mask) {
            session->event_handled = !foreign_step && !foreign_mask;
            *hold = 1;
            return capture_registers(session);
        }
        if (owned_step) return DEBUGGER_OK;
    }
    /* A target exception during our instruction must reach its own handler.
       Rearm before releasing other threads, and remove our temporary flags. */
    if (session->step_flags_set && event->thread_id == session->step_thread) {
        DebuggerError error = debugger_finish_step(session, 1);
        if (error != DEBUGGER_OK) return error;
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
    session->state.exception_code = session->event.exception_code;
    session->event_ready = 0;
    session->event_handled = session->event.kind != PLATFORM_DEBUG_EXCEPTION;
    session->hardware_hit_mask = 0;
    if (waited != PLATFORM_OK) return DEBUGGER_ERR_WAIT;
    int hold = 0;
    DebuggerError error = debugger_dispatch_event(session, &hold);
    if (error != DEBUGGER_OK) return error;
    session->event_ready = 1;
    if (hold) return DEBUGGER_OK;
    return debugger_continue_event(session);
}

DebuggerError debugger_continue_event(Debugger *session)
{
    if (platform_debug_continue(&session->event, session->event_handled) != PLATFORM_OK) return DEBUGGER_ERR_CONTINUE;
    session->state.paused = 0;
    session->state.registers_valid = 0;
    if (session->event.kind == PLATFORM_DEBUG_EXIT_PROCESS) {
        session->state = (DebuggerState){0};
        debugger_free_threads(session, 0);
        session->process_event_handle = NULL;
        session->pending_software = -1;
        session->step_flags_set = 0;
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

static DebuggerError capture_registers(Debugger *session)
{
    session->state.registers_valid = 0;
    DebugThread *thread = debugger_find_thread(session, session->event.thread_id);
    PlatformDebugContext context;
    if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    session->state.registers = context.registers;
    session->state.registers_valid = 1;
    return DEBUGGER_OK;
}
