#include "tui/help.h"

static const HelpEntry hexview_overview_entries[] = {
    { L"live bytes", L"Hex View reads only the displayed memory window every 200 ms. The left column is the target address, followed by hexadecimal bytes and an ASCII gutter." },
    { L"unreadable", L"A `??` hex cell and `?` ASCII cell mean that byte could not be read. It is distinct from a real `00` byte, which displays as `00` and `.`." },
    { L"jump",       L"Use `hex <hex_address>` from the command bar, or press `v` on an Address Table entry, to inspect any address." },
    { L"editing",    L"Type two hexadecimal digits on a readable selected byte to write it. The view always reads target memory again after the write, including after failure." },
};

static const HelpEntry hexview_key_entries[] = {
    { L"Arrow keys", L"Move the byte cursor; crossing an edge scrolls the window" },
    { L"Page Up/Down", L"Move one visible window backward or forward" },
    { L"0-9, A-F",   L"Enter the selected byte as two hexadecimal nibbles" },
    { L"g",          L"Open the command bar with `hex ` pre-filled" },
    { L"?",          L"Open this help book" },
    { L"Esc",        L"Return focus to the sidebar panel selector" },
    { L"Tab",        L"Cycle focus between sidebar, panel, and command bar" },
};

static const HelpPage hexview_pages[] = {
    { L"Overview", L"Inspect and edit raw target memory without selecting a data type.",
      hexview_overview_entries, HELP_COUNT(hexview_overview_entries) },
    { L"Keys", L"Keyboard controls when Hex View has focus.",
      hexview_key_entries, HELP_COUNT(hexview_key_entries) },
    { L"Commands", L"Every command available from the command bar.",
      tui_command_help_entries, TUI_COMMAND_HELP_COUNT },
};

const HelpBook tui_help_hexview = {
    L"Hex View Help", hexview_pages, HELP_COUNT(hexview_pages)
};
