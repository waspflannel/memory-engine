#include "tui/help.h"

static const HelpEntry addr_overview_entries[] = {
    { L"address table",   L"A persistent list of memory addresses you care about -- health, ammo, gold, etc. Each entry labels an address, shows its live value, and can be locked to hold a chosen value constant." },
    { L"adding entries",  L"From the Scanner panel, select a hit with Up/Down and press `a` to promote it. Or type `addentry <hex_addr> <type> <label>` manually in the command bar." },
    { L"live values",     L"While attached, every entry is re-read from the target process every ~200 ms. A failed read shows `err`; a missing process shows `no process`." },
    { L"persistence",     L"Entries survive detach and reload as inert addresses. Locks never cross targets and never reactivate on load." },
    { L"pagination",      L"Up/Down moves the selection cursor through entries. The list scrolls to keep the selected entry visible." },
};

static const HelpEntry addr_lock_entries[] = {
    { L"what is locking", L"Locking writes a fixed value to an address on a steady 50 ms interval. If the game tries to change health to 0, the lock loop writes your chosen value back first. This is how infinite health/ammo works." },
    { L"locking",         L"Select an entry and press `l`, or type `lockentry <index> <value>` with the value to hold. The value is parsed per the entry's type (e.g. `lockentry 0 1000` for an i32 entry)." },
    { L"unlocking",       L"Press `u` on a locked entry or type `unlockentry <index>`. The lock loop stops writing and the value moves freely again." },
    { L"write failure",   L"If a lock write fails (target process exits or memory protection changes), the entry is automatically unlocked and an error is shown in the status bar -- no silent spinning." },
    { L"lock cadence",    L"50 ms (20 writes/sec). Fast enough to beat most game tick loops without burning CPU in a tight loop." },
};

static const HelpEntry addr_keys_entries[] = {
    { L"P / I", L"Find pointer paths to the selected address / inspect its structure" },
    { L"k", L"Watch the selected numeric value; pause when a target CPU write changes it" },
    { L"Up / Down", L"Move selection cursor through entries" },
    { L"d",         L"Delete the selected entry" },
    { L"l",         L"Lock the selected entry (opens the command bar with `lockentry <index> ` pre-filled)" },
    { L"u",         L"Unlock the selected entry" },
    { L"e",         L"Rename the selected entry (opens the command bar pre-filled)" },
    { L"r",         L"Read the selected entry's address -- opens the command bar pre-filled with `read <addr> ` (type the byte count, 1-128, then Enter)" },
    { L"w",         L"Write to the selected entry's address -- opens the command bar pre-filled with `write <addr> ` (type hex byte pairs, then Enter)" },
    { L"v",         L"Open the selected entry's address in Hex View" },
    { L"?",         L"Open this help book" },
    { L"Esc",       L"Return focus to the sidebar panel selector" },
    { L"Tab",       L"Cycle focus between sidebar, panel, and command bar" },
};

static const HelpPage addr_pages[] = {
    { L"Overview",     L"What the address table is for and how entries work.",
      addr_overview_entries, HELP_COUNT(addr_overview_entries) },
    { L"Locking",      L"How value locking beats the game's writes, and the lock loop mechanics.",
      addr_lock_entries,     HELP_COUNT(addr_lock_entries) },
    { L"Commands",     L"Every command you can type for the address table.",
      tui_command_help_entries, TUI_COMMAND_HELP_COUNT },
    { L"Keys",         L"Keyboard shortcuts active when the address table panel is focused.",
      addr_keys_entries,     HELP_COUNT(addr_keys_entries) },
};

const HelpBook tui_help_address_table = {
    L"Address Table Help", addr_pages, HELP_COUNT(addr_pages)
};
