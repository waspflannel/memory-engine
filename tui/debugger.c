#include "tui_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>

static void focus_watch(void);
static void format_value(wchar_t *output, size_t capacity, const unsigned char *bytes);

void tui_watch_value(unsigned long long address, ScanType type)
{
    unsigned int size = scanner_type_width(type);
    if (!tui_state.attached) { tui_set_status(L"No process attached", TRUE); return; }
    if (tui_state.debugger) { tui_set_status(L"Already watching; stop watching first", TRUE); return; }
    if (!size || size > 8) { tui_set_status(L"Watch requires a numeric value", TRUE); return; }
    tui_state.debugger_type = type;
    tui_state.debugger_disasm = (DisasmResult){0};
    tui_debugger_result(debugger_watch(&tui_state.target, address, size, &tui_state.debugger),
                        L"Starting value watch...");
    if (tui_state.debugger) {
        debugger_get_state(tui_state.debugger, &tui_state.debugger_state);
        focus_watch();
    }
}

void tui_continue_watch(void)
{
    if (!tui_state.debugger) { tui_set_status(L"No value watch active", TRUE); return; }
    tui_debugger_result(debugger_continue(tui_state.debugger), L"Watching for changes");
}

void tui_stop_watch(void)
{
    if (!tui_state.debugger) { tui_set_status(L"No value watch active", TRUE); return; }
    if (tui_debugger_result(debugger_detach(&tui_state.debugger), L"Stopped watching; target remains attached")) {
        tui_state.debugger_state = (DebuggerState){0};
        tui_state.debugger_disasm = (DisasmResult){0};
        tui_state.debugger_scroll = 0;
    }
}

void tui_tick_debugger(void)
{
    if (!tui_state.debugger) return;
    int was_paused = tui_state.debugger_state.paused;
    int was_watching = tui_state.debugger_state.watching;
    int success = tui_debugger_result(debugger_poll(tui_state.debugger), NULL);
    debugger_get_state(tui_state.debugger, &tui_state.debugger_state);
    if (!tui_state.debugger_state.attached) {
        if (tui_detach_target()) tui_set_status(L"Target process exited", TRUE);
    } else if (!was_paused && tui_state.debugger_state.paused) {
        focus_watch();
        tui_state.debugger_disasm = (DisasmResult){0};
        if (success && tui_state.debugger_state.registers_valid)
            tui_state.debugger_disasm_error = disasm_read(&tui_state.target,
                tui_state.debugger_state.registers.rip, &tui_state.debugger_disasm);
        if (success) tui_set_status(L"Value changed; target paused", FALSE);
    } else if (success && !was_watching && tui_state.debugger_state.watching) {
        tui_set_status(L"Watching for changes", FALSE);
    }
}

void tui_debugger_key(WORD vk, WCHAR ch)
{
    if (ch == L'?') tui_open_help();
    else if (towlower(ch) == L'c') tui_continue_watch();
    else if (towlower(ch) == L's') tui_stop_watch();
    else if (towlower(ch) == L'd') {
        if (tui_detach_target()) tui_set_status(L"Detached", FALSE);
    } else if (vk == VK_UP && tui_state.debugger_scroll > 0) tui_state.debugger_scroll--;
    else if (vk == VK_DOWN) tui_state.debugger_scroll++;
    else if (vk == VK_PRIOR) {
        tui_state.debugger_scroll -= tui_state.height - 7;
        if (tui_state.debugger_scroll < 0) tui_state.debugger_scroll = 0;
    } else if (vk == VK_NEXT) tui_state.debugger_scroll += tui_state.height - 7;
}

void tui_draw_debugger(Screen *screen, int x, int top, int bottom)
{
    const WORD normal = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    const WORD disabled = FOREGROUND_INTENSITY;
    const DebuggerState *state = &tui_state.debugger_state;
    const wchar_t *actions[] = {L"[C] Continue", L"[S] Stop watching", L"[D] Detach"};
    int width = screen->width - x - 1;
    int footer_rows = width >= 43 ? 1 : 3;
    int visible = bottom - top + 1 - footer_rows;
    wchar_t lines[40][DISASM_TEXT_MAX + 32];
    int count = 0;
    if (!tui_state.debugger) {
        wcscpy_s(lines[count++], _countof(lines[0]), L"Select a numeric value in Scanner or AddrTable; press k to watch.");
    } else {
        wcscpy_s(lines[count++], _countof(lines[0]), state->paused ? (state->value_valid && state->registers_valid &&
                 memcmp(state->before, state->after, state->size) != 0 ? L"Value changed - paused" : L"Watch paused") :
                 state->watching ? L"Watching for changes" : L"Starting watch...");
        swprintf_s(lines[count++], _countof(lines[0]), L"Address: %016llX", state->address);
        swprintf_s(lines[count++], _countof(lines[0]), L"Type: %s", tui_scan_type_name(tui_state.debugger_type));
        if (state->value_valid) {
            wchar_t value[64];
            format_value(value, _countof(value), state->before);
            swprintf_s(lines[count++], _countof(lines[0]), L"Before: %s", value);
            format_value(value, _countof(value), state->after);
            swprintf_s(lines[count++], _countof(lines[0]), L"After: %s", value);
        }
        if (state->paused) {
            swprintf_s(lines[count++], _countof(lines[0]), L"Stopped thread: %u", state->thread_id);
            if (state->registers_valid) {
                wcscpy_s(lines[count++], _countof(lines[0]), L"Next instructions (after write):");
                if (tui_state.debugger_disasm_error != PLATFORM_OK || !tui_state.debugger_disasm.count)
                    wcscpy_s(lines[count++], _countof(lines[0]), L"Disassembly unavailable");
                else for (size_t i = 0; i < tui_state.debugger_disasm.count && i < 3; i++) {
                    const DisasmInstruction *instruction = &tui_state.debugger_disasm.instructions[i];
                    swprintf_s(lines[count++], _countof(lines[0]), L"%016llX %S", instruction->address, instruction->text);
                }
                const DebuggerRegisters *r = &state->registers;
                const wchar_t *names[] = {L"RIP",L"RAX",L"RBX",L"RCX",L"RDX",L"RSI",L"RDI",L"RBP",L"RSP",
                                         L"R8",L"R9",L"R10",L"R11",L"R12",L"R13",L"R14",L"R15"};
                const unsigned long long values[] = {r->rip,r->rax,r->rbx,r->rcx,r->rdx,r->rsi,r->rdi,r->rbp,r->rsp,
                                                    r->r8,r->r9,r->r10,r->r11,r->r12,r->r13,r->r14,r->r15};
                for (size_t i = 0; i < _countof(values); i++)
                    swprintf_s(lines[count++], _countof(lines[0]), L"%-3s %016llX", names[i], values[i]);
                swprintf_s(lines[count++], _countof(lines[0]), L"EFLAGS %08X", r->eflags);
            } else wcscpy_s(lines[count++], _countof(lines[0]), L"Registers unavailable");
        }
    }
    int rows = 0;
    for (int i = 0; i < count; i++) rows += ((int)wcslen(lines[i]) + width - 1) / width;
    int max_scroll = rows > visible ? rows - visible : 0;
    if (tui_state.debugger_scroll > max_scroll) tui_state.debugger_scroll = max_scroll;
    int row = 0;
    for (int i = 0; i < count; i++) {
        int length = (int)wcslen(lines[i]);
        for (int offset = 0; offset < length; offset += width, row++) {
            int y = top + row - tui_state.debugger_scroll;
            if (y < top || y >= top + visible) continue;
            for (int column = 0; column < width && offset + column < length; column++)
                screen_put(screen, x + column, y, lines[i][offset + column], normal);
        }
    }
    int action_x = x;
    for (int i = 0; i < 3; i++) {
        int enabled = i == 0 ? state->paused && state->watching : i == 1 ? tui_state.debugger != NULL : tui_state.attached;
        int y = bottom - footer_rows + 1 + (footer_rows == 1 ? 0 : i);
        screen_text(screen, action_x, y, actions[i], enabled ? normal : disabled);
        if (footer_rows == 1) action_x += (int)wcslen(actions[i]) + 2;
    }
}

static void focus_watch(void)
{
    tui_state.panel = PANEL_DEBUGGER;
    tui_state.sidebar_idx = PANEL_DEBUGGER;
    tui_state.focus = FOCUS_MAIN;
    tui_state.help_open = 0;
    tui_state.debugger_scroll = 0;
}

static void format_value(wchar_t *output, size_t capacity, const unsigned char *bytes)
{
#define VALUE(kind, format) { kind value; memcpy(&value, bytes, sizeof(value)); swprintf_s(output, capacity, format, value); break; }
    switch (tui_state.debugger_type) {
    case SCAN_TYPE_I8: VALUE(int8_t, L"%d")
    case SCAN_TYPE_I16: VALUE(int16_t, L"%d")
    case SCAN_TYPE_I32: VALUE(int32_t, L"%d")
    case SCAN_TYPE_I64: VALUE(int64_t, L"%lld")
    case SCAN_TYPE_U8: VALUE(uint8_t, L"%u")
    case SCAN_TYPE_U16: VALUE(uint16_t, L"%u")
    case SCAN_TYPE_U32: VALUE(uint32_t, L"%u")
    case SCAN_TYPE_U64: VALUE(uint64_t, L"%llu")
    case SCAN_TYPE_F32: VALUE(float, L"%.9g")
    case SCAN_TYPE_F64: VALUE(double, L"%.17g")
    default: wcscpy_s(output, capacity, L"?"); break;
    }
#undef VALUE
}
