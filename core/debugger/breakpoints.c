#include "core/debugger/debugger_internal.h"

static int free_breakpoint(Debugger *session);
static unsigned long long slot_mask(unsigned int slot);

DebuggerError debugger_add_software(Debugger *session, unsigned long long address, unsigned int *index)
{
    if (!session || !index || !session->state.attached) return DEBUGGER_ERR_INVALID_PARAM;
    if (!session->state.paused) return DEBUGGER_ERR_NOT_PAUSED;
    for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
        DebuggerBreakpoint *breakpoint = &session->state.breakpoints[i];
        if (breakpoint->active && breakpoint->kind == DEBUGGER_SOFTWARE && breakpoint->address == address) {
            return DEBUGGER_ERR_INVALID_PARAM;
        }
    }
    int free_index = free_breakpoint(session);
    if (free_index < 0) return DEBUGGER_ERR_CAPACITY;
    BreakpointRestore *restore = &session->restore[free_index];
    *restore = (BreakpointRestore){0};
    size_t read = 0;
    if (platform_read_memory(session->target.handle, address, &restore->original_byte, 1, &read) != PLATFORM_OK || read != 1) {
        return DEBUGGER_ERR_PATCH;
    }
    if (restore->original_byte == 0xCC) return DEBUGGER_ERR_UNSUPPORTED;
    *index = (unsigned int)free_index;
    session->state.breakpoints[free_index] = (DebuggerBreakpoint){1, DEBUGGER_SOFTWARE, address, 0, 0};
    if (platform_debug_patch(session->target.handle, address, 0xCC, &restore->protection) != PLATFORM_OK) {
        restore->repair_required = 1;
        (void)debugger_remove(session, *index); /* Successful rollback discards the entry. */
        return DEBUGGER_ERR_PATCH;
    }
    return DEBUGGER_OK;
}

DebuggerError debugger_add_hardware(Debugger *session, unsigned int thread_id,
                                    unsigned long long address, unsigned int *index)
{
    if (!session || !index || !session->state.attached) return DEBUGGER_ERR_INVALID_PARAM;
    if (!session->state.paused) return DEBUGGER_ERR_NOT_PAUSED;
    DebugThread *thread = debugger_find_thread(session, thread_id);
    if (!thread) return DEBUGGER_ERR_NOT_FOUND;
    /* Reject unmapped addresses rather than claiming an unusable breakpoint armed. */
    unsigned char byte;
    size_t read = 0;
    if (platform_read_memory(session->target.handle, address, &byte, 1, &read) != PLATFORM_OK || read != 1) {
        return DEBUGGER_ERR_PATCH;
    }
    int free_index = free_breakpoint(session);
    if (free_index < 0) return DEBUGGER_ERR_CAPACITY;
    PlatformDebugContext context;
    if (platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    unsigned int slot;
    for (slot = 0; slot < 4; slot++) {
        if (!(context.dr7 & (3ull << (slot * 2)))) break;
    }
    if (slot == 4) return DEBUGGER_ERR_CAPACITY;
    BreakpointRestore *restore = &session->restore[free_index];
    *restore = (BreakpointRestore){0};
    restore->original_dr = context.dr[slot];
    restore->original_dr7 = context.dr7 & slot_mask(slot);
    restore->original_dr6 = context.dr6 & (1ull << slot);
    context.dr[slot] = address;
    context.dr7 = (context.dr7 & ~slot_mask(slot)) | (1ull << (slot * 2));
    context.dr6 &= ~(1ull << slot);
    *index = (unsigned int)free_index;
    session->state.breakpoints[free_index] = (DebuggerBreakpoint){1, DEBUGGER_HARDWARE, address, thread_id, slot};
    if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) {
        restore->repair_required = 1;
        (void)debugger_remove(session, *index);
        return DEBUGGER_ERR_CONTEXT;
    }
    return DEBUGGER_OK;
}

DebuggerError debugger_remove(Debugger *session, unsigned int index)
{
    if (!session || !session->state.attached || index >= DEBUGGER_MAX_BREAKPOINTS) return DEBUGGER_ERR_INVALID_PARAM;
    if (!session->state.paused) return DEBUGGER_ERR_NOT_PAUSED;
    DebuggerBreakpoint *breakpoint = &session->state.breakpoints[index];
    BreakpointRestore *restore = &session->restore[index];
    if (!breakpoint->active) return DEBUGGER_ERR_NOT_FOUND;
    if (breakpoint->kind == DEBUGGER_SOFTWARE) {
        if (platform_debug_patch(session->target.handle, breakpoint->address, restore->original_byte,
                                 &restore->protection) != PLATFORM_OK) return DEBUGGER_ERR_PATCH;
        if (session->pending_software == (int)index) {
            DebuggerError error = debugger_finish_step(session, 0);
            if (error != DEBUGGER_OK) return error;
        }
    } else {
        DebugThread *thread = debugger_find_thread(session, breakpoint->thread_id);
        if (thread) {
            PlatformDebugContext context;
            if (platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
            context.dr[breakpoint->slot] = restore->original_dr;
            context.dr7 = (context.dr7 & ~slot_mask(breakpoint->slot)) | restore->original_dr7;
            context.dr6 = (context.dr6 & ~(1ull << breakpoint->slot)) | restore->original_dr6;
            if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        }
        if (session->event.thread_id == breakpoint->thread_id) {
            session->hardware_hit_mask &= ~(1ull << breakpoint->slot);
        }
    }
    *breakpoint = (DebuggerBreakpoint){0};
    *restore = (BreakpointRestore){0};
    return DEBUGGER_OK;
}

DebuggerError debugger_resume_threads(Debugger *session)
{
    for (DebugThread *thread = session->threads; thread; thread = thread->next) {
        if (!thread->suspended) continue;
        if (platform_debug_resume(thread->handle) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        thread->suspended = 0;
    }
    return DEBUGGER_OK;
}

DebuggerError debugger_finish_step(Debugger *session, int rearm)
{
    if (session->step_flags_set) {
        DebugThread *thread = debugger_find_thread(session, session->step_thread);
        if (thread) {
            PlatformDebugContext context;
            if (platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
            context.registers.eflags = (context.registers.eflags & ~(TRAP_FLAG | RESUME_FLAG)) | session->step_flags;
            context.dr6 &= ~SINGLE_STEP_STATUS;
            if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        }
    }
    if (rearm && session->pending_software >= 0) {
        DebuggerBreakpoint *breakpoint = &session->state.breakpoints[session->pending_software];
        BreakpointRestore *restore = &session->restore[session->pending_software];
        if (platform_debug_patch(session->target.handle, breakpoint->address, 0xCC,
                                 &restore->protection) != PLATFORM_OK) return DEBUGGER_ERR_PATCH;
    }
    DebuggerError error = debugger_resume_threads(session);
    if (error != DEBUGGER_OK) return error;
    session->pending_software = -1;
    session->step_flags_set = 0;
    session->step_event = 0;
    session->step_hardware_resumed = 0;
    return DEBUGGER_OK;
}

DebuggerError debugger_start_step(Debugger *session)
{
    for (DebugThread *thread = session->threads; thread; thread = thread->next) {
        if (thread->id == session->step_thread || thread->breakin || thread->suspended) continue;
        if (platform_debug_suspend(thread->handle) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        thread->suspended = 1;
    }
    DebugThread *thread = debugger_find_thread(session, session->step_thread);
    PlatformDebugContext context;
    if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    context.registers.eflags |= TRAP_FLAG;
    context.dr6 &= ~SINGLE_STEP_STATUS;
    if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    session->step_flags_set = 1;
    return DEBUGGER_OK;
}

static int free_breakpoint(Debugger *session)
{
    for (int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
        if (!session->state.breakpoints[i].active) return i;
    }
    return -1;
}

static unsigned long long slot_mask(unsigned int slot)
{
    return (3ull << (slot * 2)) | (15ull << (16 + slot * 4));
}
