#include "core/debugger/debugger_internal.h"
#include "core/memory/memory.h"

static unsigned long long slot_mask(unsigned int slot);

DebuggerError debugger_arm_thread(Debugger *session, DebugThread *thread)
{
    if (thread->configured) return DEBUGGER_OK;
    PlatformDebugContext context;
    if (platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    if (thread->slot < 0) {
        unsigned int slot;
        for (slot = 0; slot < 4; slot++) {
            if (!(context.dr7 & (3ull << (slot * 2)))) break;
        }
        if (slot == 4) return DEBUGGER_ERR_CAPACITY;
        thread->slot = (int)slot;
        thread->original_dr = context.dr[slot];
        thread->original_dr7 = context.dr7 & slot_mask(slot);
        thread->original_dr6 = context.dr6 & (1ull << slot);
    }
    unsigned int slot = (unsigned int)thread->slot;
    unsigned int length = session->state.size == 8 ? 2 : session->state.size - 1;
    context.dr[slot] = session->state.address;
    /* RW=01 watches writes; LEN encodes 1/2/4/8 bytes as 00/01/11/10. */
    context.dr7 = (context.dr7 & ~slot_mask(slot)) | (1ull << (slot * 2)) |
                  ((1ull | ((unsigned long long)length << 2)) << (16 + slot * 4));
    context.dr6 &= ~(1ull << slot);
    /* Retain the saved slot even if SetThreadContext fails, for cleanup retry. */
    if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
    thread->configured = 1;
    return DEBUGGER_OK;
}

DebuggerError debugger_restore_threads(Debugger *session)
{
    for (DebugThread *thread = session->threads; thread; thread = thread->next) {
        if (thread->slot < 0) continue;
        unsigned int slot = (unsigned int)thread->slot;
        PlatformDebugContext context;
        if (platform_debug_get_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        context.dr[slot] = thread->original_dr;
        context.dr7 = (context.dr7 & ~slot_mask(slot)) | thread->original_dr7;
        context.dr6 = (context.dr6 & ~(1ull << slot)) | thread->original_dr6;
        if (platform_debug_set_context(thread->handle, &context) != PLATFORM_OK) return DEBUGGER_ERR_CONTEXT;
        if (thread->id == session->event.thread_id) session->hit_mask = 0;
        thread->slot = -1;
        thread->configured = 0;
    }
    return DEBUGGER_OK;
}

DebuggerError debugger_read_value(Debugger *session, unsigned char *value)
{
    return memory_read(&session->target, session->state.address, value, session->state.size) == PLATFORM_OK
           ? DEBUGGER_OK : DEBUGGER_ERR_READ;
}

static unsigned long long slot_mask(unsigned int slot)
{
    return (3ull << (slot * 2)) | (15ull << (16 + slot * 4));
}
