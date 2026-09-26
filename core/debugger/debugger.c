#include <stdlib.h>
#include <string.h>

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

/* Forward declarations — definitions at bottom of file. */
static DebugThread *find_thread(Debugger *session, unsigned int id);
static void free_threads(Debugger *session, int close_handles);
static DebuggerError capture_registers(Debugger *session);
static DebuggerError resume_threads(Debugger *session);
static DebuggerError finish_step(Debugger *session, int rearm);
static DebuggerError start_step(Debugger *session);
static DebuggerError dispatch_event(Debugger *session, int *hold);
static DebuggerError poll_event(Debugger *session, unsigned int timeout);
static DebuggerError continue_event(Debugger *session);
static int free_breakpoint(Debugger *session);
static unsigned long long slot_mask(unsigned int slot);

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
    return poll_event(session, 0);
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
        DebuggerError error = dispatch_event(session, &hold);
        if (error != DEBUGGER_OK) return error;
        session->event_ready = 1;
    }
    for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
        if (session->state.breakpoints[i].active && session->restore[i].repair_required) {
            return DEBUGGER_ERR_PATCH;
        }
    }
    if (session->pending_software >= 0 && !session->step_flags_set) {
        DebuggerError error = start_step(session);
        if (error != DEBUGGER_OK) return error;
    }
    if (session->hardware_hit_mask) {
        DebugThread *thread = find_thread(session, session->event.thread_id);
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
    return continue_event(session);
}

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
    DebugThread *thread = find_thread(session, thread_id);
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
            DebuggerError error = finish_step(session, 0);
            if (error != DEBUGGER_OK) return error;
        }
    } else {
        DebugThread *thread = find_thread(session, breakpoint->thread_id);
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
        DebuggerError error = poll_event(current, 0);
        if (error != DEBUGGER_OK) return error;
    }
    if (current->state.attached && !current->state.paused) {
        DebuggerError error = debugger_pause(current);
        if (error != DEBUGGER_OK) return error;
        /* Bounded drain: a failed stop leaves the borrowed target and session intact. */
        for (unsigned int attempt = 0; attempt < 500 && current->state.attached && !current->state.paused; attempt++) {
            error = poll_event(current, 10);
            if (error != DEBUGGER_OK) return error;
        }
        if (current->state.attached && !current->state.paused) return DEBUGGER_ERR_DETACH;
    }
    if (current->state.attached) {
        if (!current->event_ready) {
            int hold = 0;
            DebuggerError error = dispatch_event(current, &hold);
            if (error != DEBUGGER_OK) return error;
            current->event_ready = 1;
        }
        for (unsigned int i = 0; i < DEBUGGER_MAX_BREAKPOINTS; i++) {
            if (!current->state.breakpoints[i].active) continue;
            DebuggerError error = debugger_remove(current, i);
            if (error != DEBUGGER_OK) return error;
        }
        DebuggerError error = resume_threads(current);
        if (error != DEBUGGER_OK) return error;
        error = continue_event(current);
        if (error != DEBUGGER_OK) return error;
        if (platform_debug_stop(current->target.pid) != PLATFORM_OK) return DEBUGGER_ERR_DETACH;
    }
    free_threads(current, 1);
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

/* ---- Static helpers ---- */

static DebugThread *find_thread(Debugger *session, unsigned int id)
{
    for (DebugThread *thread = session->threads; thread; thread = thread->next) {
        if (thread->id == id) return thread;
    }
    return NULL;
}

static void free_threads(Debugger *session, int close_handles)
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
    DebugThread *thread = find_thread(session, session->event.thread_id);
    PlatformDebugContext context;
    if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    session->state.registers = context.registers;
    session->state.registers_valid = 1;
    return DEBUGGER_OK;
}

static DebuggerError resume_threads(Debugger *session)
{
    for (DebugThread *thread = session->threads; thread; thread = thread->next) {
        if (!thread->suspended) continue;
        if (platform_debug_resume(thread->handle) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        thread->suspended = 0;
    }
    return DEBUGGER_OK;
}

static DebuggerError finish_step(Debugger *session, int rearm)
{
    if (session->step_flags_set) {
        DebugThread *thread = find_thread(session, session->step_thread);
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
    DebuggerError error = resume_threads(session);
    if (error != DEBUGGER_OK) return error;
    session->pending_software = -1;
    session->step_flags_set = 0;
    session->step_event = 0;
    session->step_hardware_resumed = 0;
    return DEBUGGER_OK;
}

static DebuggerError start_step(Debugger *session)
{
    for (DebugThread *thread = session->threads; thread; thread = thread->next) {
        if (thread->id == session->step_thread || thread->breakin || thread->suspended) continue;
        if (platform_debug_suspend(thread->handle) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        thread->suspended = 1;
    }
    DebugThread *thread = find_thread(session, session->step_thread);
    PlatformDebugContext context;
    if (!thread || platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    context.registers.eflags |= TRAP_FLAG;
    context.dr6 &= ~SINGLE_STEP_STATUS;
    if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    session->step_flags_set = 1;
    return DEBUGGER_OK;
}

static DebuggerError dispatch_event(Debugger *session, int *hold)
{
    PlatformDebugEvent *event = &session->event;
    *hold = 0;
    switch (event->kind) {
    case PLATFORM_DEBUG_CREATE_THREAD: {
        if (event->process_handle) {
            session->process_event_handle = event->process_handle;
            event->process_handle = NULL;
        }
        DebugThread *thread = find_thread(session, event->thread_id);
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
        if (session->pending_software >= 0 && session->step_thread == event->thread_id) return finish_step(session, 1);
        return DEBUGGER_OK;
    }
    case PLATFORM_DEBUG_EXIT_PROCESS:
        return DEBUGGER_OK;
    case PLATFORM_DEBUG_EXCEPTION:
        break;
    default:
        return DEBUGGER_OK;
    }

    DebugThread *thread = find_thread(session, event->thread_id);
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
            DebuggerError error = finish_step(session, 1);
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
        DebuggerError error = finish_step(session, 1);
        if (error != DEBUGGER_OK) return error;
    }
    return DEBUGGER_OK;
}

static DebuggerError poll_event(Debugger *session, unsigned int timeout)
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
    DebuggerError error = dispatch_event(session, &hold);
    if (error != DEBUGGER_OK) return error;
    session->event_ready = 1;
    if (hold) return DEBUGGER_OK;
    return continue_event(session);
}

static DebuggerError continue_event(Debugger *session)
{
    if (platform_debug_continue(&session->event, session->event_handled) != PLATFORM_OK) return DEBUGGER_ERR_CONTINUE;
    session->state.paused = 0;
    session->state.registers_valid = 0;
    if (session->event.kind == PLATFORM_DEBUG_EXIT_PROCESS) {
        session->state = (DebuggerState){0};
        free_threads(session, 0);
        session->process_event_handle = NULL;
        session->pending_software = -1;
        session->step_flags_set = 0;
    }
    session->event = (PlatformDebugEvent){0};
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
