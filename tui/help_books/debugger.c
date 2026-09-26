#include "tui/help.h"

static const HelpEntry overview[] = {
    { L"start", L"Attach a process first, then run debug. The initial Windows breakpoint pauses the process. Use continue to run and break to pause again." },
    { L"software", L"While paused, swbreak <hex_address> replaces a code byte with INT3. The original instruction is restored and executed on resume, then the breakpoint is rearmed." },
    { L"hardware", L"While paused, hwbreak <decimal_tid> <hex_address> sets an execution breakpoint on that thread only. The panel lists the thread and slot. At most four hardware slots are available per thread." },
    { L"registers", L"Paused registers belong to the event thread shown at the top. Running or failed context reads do not display stale register values. This debugger supports native x64 targets." },
    { L"cleanup", L"delbreak <index> removes a breakpoint while paused. undebug restores all patches and debug registers and resumes the target. detach and quit do the same before closing the process; failed cleanup retains the session for retry." },
    { L"scope", L"Hardware breakpoints are execution-only. Conditional breakpoints, register editing, and user-controlled single stepping are not implemented." },
};

static const HelpEntry keys[] = {
    { L"Up / Down", L"Scroll registers and the breakpoint list" },
    { L"Page Up/Down", L"Scroll one visible page" },
    { L"d", L"Open disassembly at the paused instruction pointer when registers are valid" },
    { L"?", L"Open this help book" },
    { L"Esc / Tab", L"Return to the sidebar or cycle focus to the command bar" },
};

static const HelpPage pages[] = {
    { L"Overview", L"Pause and inspect a native x64 process.", overview, HELP_COUNT(overview) },
    { L"Commands", L"Commands available from the command bar.", tui_command_help_entries, TUI_COMMAND_HELP_COUNT },
    { L"Keys", L"Shortcuts when the Debugger panel is focused.", keys, HELP_COUNT(keys) },
};

const HelpBook tui_help_debugger = { L"Debugger Help", pages, HELP_COUNT(pages) };
