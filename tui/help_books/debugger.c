#include "tui/help.h"

static const HelpEntry overview[] = {
    { L"start", L"Attach a process, select a numeric Scanner result or AddrTable entry and press k. Or enter watch <hex_address> <type>. One value is watched across all target threads." },
    { L"change", L"The target pauses after a CPU write changes the watched bytes. Same-value writes continue automatically. External memory edits and address locks do not themselves trigger CPU watchpoints." },
    { L"inspect", L"The screen shows before/after values, the stopped thread, registers and disassembly at its next instruction. RIP is after the write, not the exact writing instruction. Up/Down scrolls details." },
    { L"stop watching", L"S or unwatch removes the watch and resumes the target. Ordinary memory access stays attached. D or detach removes the watch and disconnects from the target." },
    { L"scope", L"Native x64 only. Numeric sizes 1, 2, 4 or 8 bytes; address must be aligned to that size. Strings/AOB are unsupported. A second watch is rejected. Failed cleanup keeps the session available for retry." },
};
static const HelpEntry keys[] = {
    { L"C", L"Continue after a value change, retaining the watch" },
    { L"S", L"Stop watching; keep memory access attached" },
    { L"D", L"Detach from the target" },
    { L"Up/Down, PgUp/PgDn", L"Scroll the value details, next instructions and registers" },
    { L"?", L"Open this help book" },
    { L"Esc / Tab", L"Return to the sidebar or cycle focus to the command bar" },
};
static const HelpPage pages[] = {
    { L"Overview", L"Watch one value and inspect changes.", overview, HELP_COUNT(overview) },
    { L"Commands", L"Commands available from the command bar.", tui_command_help_entries, TUI_COMMAND_HELP_COUNT },
    { L"Keys", L"Shortcuts when the Debugger panel is focused.", keys, HELP_COUNT(keys) },
};
const HelpBook tui_help_debugger = { L"Value Watch Help", pages, HELP_COUNT(pages) };
