#include "tui/help.h"

static const HelpEntry disasm_overview_entries[] = {
    { L"instructions", L"Disassembles readable target memory as x64 instructions with addresses, raw bytes, mnemonics, and Intel-style operands." },
    { L"jump",         L"Use `disasm <hex_address>` to re-anchor decoding at a known instruction boundary. Starting mid-instruction produces the CPU's normal variable-length decode from that byte." },
    { L"branches",     L"Direct relative calls and jumps show a numeric target. Select one and press `f` to follow it." },
    { L"unreadable",   L"An unreadable code region reports an explicit error; the panel never substitutes stale or zeroed bytes." },
};

static const HelpEntry disasm_keys_entries[] = {
    { L"Up / Down", L"Move through decoded instructions; Down at the end reads the next window" },
    { L"Page Up/Down", L"Move the selection by one visible screen of instructions" },
    { L"f",         L"Follow the selected direct relative call or branch" },
    { L"g",         L"Open the command bar with `disasm ` pre-filled" },
    { L"?",         L"Open this help book" },
    { L"Esc",       L"Return focus to the sidebar panel selector" },
    { L"Tab",       L"Cycle focus between sidebar, panel, and command bar" },
};

static const HelpPage disasm_pages[] = {
    { L"Overview", L"Read-only x64 disassembly for a target code region.",
      disasm_overview_entries, HELP_COUNT(disasm_overview_entries) },
    { L"Commands", L"Every command available from the command bar.",
      tui_command_help_entries, TUI_COMMAND_HELP_COUNT },
    { L"Keys", L"Keyboard shortcuts active when the Disasm panel is focused.",
      disasm_keys_entries, HELP_COUNT(disasm_keys_entries) },
};

const HelpBook tui_help_disasm = {
    L"Disasm Help", disasm_pages, HELP_COUNT(disasm_pages)
};
