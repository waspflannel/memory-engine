#include "tui/help.h"

static const HelpEntry proc_overview_entries[] = {
    { L"process list",   L"Enumerates running processes on this machine via the Win32 toolhelp snapshot -- one row per process showing its PID and image name." },
    { L"why attach",     L"Pick the game (or any process) whose memory you want to inspect. The Scanner and Address Table panels only work while a target is attached." },
    { L"privilege",      L"Attaching calls `process_enable_privilege` first to request `SeDebugPrivilege`, so you can open processes running at higher integrity levels." },
    { L"re-attach",      L"Selecting another process and pressing Enter detaches from the current target (tearing down the scanner session and clearing the address table's target pointer) before attaching to the new one." },
    { L"search <name>",  L"Type `search <substring>` in the command bar to filter the list to image names containing <substring> (case-insensitive). `search` with no argument clears the filter. On the Processes panel, `/` pre-fills the command bar with `search `." },
};

static const HelpEntry proc_commands_entries[] = {
    { L"attach <pid>",      L"attach to a running target process by its numeric PID -- the entry didn't open via Enter or you copied a PID from Task Manager" },
    { L"detach",            L"detach from the current process (tears down the scanner session and clears the address table's target pointer) -- table entries are preserved" },
    { L"search <name>",    L"filter the Processes panel to image names containing <name> (case-insensitive); `search` alone clears the filter. On the Processes panel, `/` pre-fills the command bar with `search `." },
    { L"read <addr> <n>",   L"read `n` bytes (1-512) from a hex address in the target process; bytes are shown in the status bar as hex" },
    { L"write <addr> <hex>",L"write raw hex bytes (e.g. `write 0x1234ABCD 90 90`) to an address in the target process" },
    { L"scan <value>",      L"first scan: walk every readable byte of the target and keep addresses matching the value (Scanner panel)" },
    { L"next <value>",      L"next scan: re-read surviving addresses, keeping only those that now match the new value (Scanner panel)" },
    { L"type <name>",       L"set the value type -- i8|i16|i32|i64|u8|u16|u32|u64|f32|f64|string|aob (Scanner panel)" },
    { L"strenc a|u",        L"set string encoding to `ascii` or `utf16` for string scans" },
    { L"addentry",          L"`addentry <hex_addr> <type> <label>` -- add a memory address to the address table for live tracking" },
    { L"delentry",          L"`delentry <index>` -- remove an entry from the address table by its 0-based index" },
    { L"entrylabel",        L"`entrylabel <index> <new_label>` -- rename an existing address table entry" },
    { L"lockentry",         L"`lockentry <index> <value>` -- write a fixed value to an entry every 50 ms (infinite health/ammo)" },
    { L"unlockentry",       L"`unlockentry <index>` -- stop the lock loop on an entry so its value moves freely again" },
    { L"saveentry",         L"`saveentry <filename>` -- persist the current address table to a human-readable text file" },
    { L"loadentry",         L"`loadentry <filename>` -- restore a previously saved address table from file" },
    { L"help / ?",          L"open this help book for the focused panel" },
    { L"quit / exit",       L"close the memory engine" },
};

static const HelpEntry proc_keys_entries[] = {
    { L"Up / Down", L"Move selection cursor through the process list; the list scrolls to keep the selected row visible" },
    { L"Enter",     L"Attach to the highlighted process -- opens a handle, starts a scanner session (type i32, mode exact), and wires the address table to this target" },
    { L"F5",        L"Refresh the process list (some apps started after MemForge launched won't be in the initial snapshot). The active search filter survives a refresh." },
    { L"/",         L"Jump to the command bar pre-filled with `search ` -- type a substring (case-insensitive) and Enter to filter the list" },
    { L"Esc",       L"If a search filter is active, clears it and shows the full list; otherwise returns focus to the sidebar panel selector" },
    { L"?",         L"Open this help book" },
    { L"Tab",       L"Cycle focus between sidebar, panel, and command bar" },
};

static const HelpPage proc_pages[] = {
    { L"Overview", L"What the process list is and why you attach to a target here.",
      proc_overview_entries, HELP_COUNT(proc_overview_entries) },
    { L"Commands", L"Every command you can type in the command bar -- visible here for parity with the other panels.",
      proc_commands_entries, HELP_COUNT(proc_commands_entries) },
    { L"Keys",     L"Keyboard shortcuts active when the Processes panel is focused.",
      proc_keys_entries,     HELP_COUNT(proc_keys_entries) },
};

static const HelpBook proc_book = {
    L"Processes Help", proc_pages, HELP_COUNT(proc_pages)
};

const HelpBook *tui_help_processes_book(void) { return &proc_book; }