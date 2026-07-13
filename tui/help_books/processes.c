#include "tui/help.h"

static const HelpEntry proc_overview_entries[] = {
    { L"process list",   L"Enumerates running processes on this machine via the Win32 toolhelp snapshot -- one row per process showing its PID and image name." },
    { L"why attach",     L"Pick the game (or any process) whose memory you want to inspect. The Scanner and Address Table panels only work while a target is attached." },
    { L"privilege",      L"Attaching calls `process_enable_privilege` first to request `SeDebugPrivilege`, so you can open processes running at higher integrity levels." },
    { L"re-attach",      L"Selecting another process and pressing Enter detaches from the current target (tearing down the scanner session and clearing the address table's target pointer) before attaching to the new one." },
};

static const HelpEntry proc_keys_entries[] = {
    { L"Up / Down", L"Move selection cursor through the process list; the list scrolls to keep the selected row visible" },
    { L"Enter",     L"Attach to the highlighted process -- opens a handle, starts a scanner session (type i32, mode exact), and wires the address table to this target" },
    { L"F5",        L"Refresh the process list (some apps started after MemForge launched won't be in the initial snapshot)" },
    { L"?",         L"Open this help book" },
    { L"Esc",       L"Return focus to the sidebar panel selector" },
    { L"Tab",       L"Cycle focus between sidebar, panel, and command bar" },
};

static const HelpPage proc_pages[] = {
    { L"Overview", L"What the process list is and why you attach to a target here.",
      proc_overview_entries, HELP_COUNT(proc_overview_entries) },
    { L"Keys",     L"Keyboard shortcuts active when the Processes panel is focused.",
      proc_keys_entries,     HELP_COUNT(proc_keys_entries) },
};

static const HelpBook proc_book = {
    L"Processes Help", proc_pages, HELP_COUNT(proc_pages)
};

const HelpBook *tui_help_processes_book(void) { return &proc_book; }