#include "tui/help.h"

static const HelpEntry addr_overview_entries[] = {
    { L"address table",   L"A persistent list of memory addresses you care about -- health, ammo, gold, etc. Each entry labels an address, shows its live value, and can be locked to hold a chosen value constant." },
    { L"adding entries",  L"From the Scanner panel, select a hit with Up/Down and press `a` to promote it. Or type `addentry <hex_addr> <type> <label>` manually in the command bar." },
    { L"live values",     L"While attached, every visible entry is re-read from the target process every ~200 ms. A failed read shows `err`; a missing process shows `no process`; variable-width types show `var`." },
    { L"pagination",      L"Up/Down moves the selection cursor through entries. The list scrolls to keep the selected entry visible." },
};

static const HelpEntry addr_lock_entries[] = {
    { L"what is locking", L"Locking writes a fixed value to an address on a steady 50 ms interval. If the game tries to change health to 0, the lock loop writes your chosen value back first. This is how infinite health/ammo works." },
    { L"locking",         L"Select an entry and press `l`, or type `lockentry <index> <value>` with the value to hold. The value is parsed per the entry's type (e.g. `lockentry 0 1000` for an i32 entry)." },
    { L"unlocking",       L"Press `u` on a locked entry or type `unlockentry <index>`. The lock loop stops writing and the value moves freely again." },
    { L"write failure",   L"If a lock write fails (target process exits or memory protection changes), the entry is automatically unlocked and an error is shown in the status bar -- no silent spinning." },
    { L"lock cadence",    L"50 ms (20 writes/sec). Fast enough to beat most game tick loops without burning CPU in a tight loop." },
};

static const HelpEntry addr_manage_entries[] = {
    { L"attach <pid>",      L"attach to a running process by its numeric PID -- required before any address can be read, written, or scanned" },
    { L"detach",            L"detach from the current process and tear down the scanner session; the table itself is preserved" },
    { L"search <name>",     L"filter the Processes panel to image names containing <name> (case-insensitive); `search` alone clears the filter" },
    { L"read <addr> <n>",   L"read `n` bytes (1-512) from a hex address in the target; bytes are shown in the status bar as hex. On the Address Table panel, press `r` on a selected entry to pre-fill `read <addr> `." },
    { L"write <addr> <hex>",L"write raw hex bytes to an address in the target process. On the Address Table panel, press `w` on a selected entry to pre-fill `write <addr> `." },
    { L"scan <value>",      L"first scan: walk every readable byte and keep addresses matching the value for the current type (Scanner panel)" },
    { L"next <value>",      L"next scan: re-read surviving addresses, keeping those that still match (Scanner panel)" },
    { L"type <name>",       L"set the value type -- i8|i16|i32|i64|u8|u16|u32|u64|f32|f64|string|aob (Scanner panel)" },
    { L"strenc a|u",        L"set string encoding to `ascii` or `utf16` for string scans" },
    { L"addentry",          L"`addentry <hex_addr> <type> <label>` -- add a memory address to the address table for live tracking" },
    { L"delentry / d",      L"`delentry <index>` or select and press `d` to remove an entry from the table." },
    { L"entrylabel / e",    L"`entrylabel <index> <new_label>` or select and press `e` to rename an entry." },
    { L"lockentry / l",     L"`lockentry <index> <value>` -- write a fixed value to an entry every 50 ms (infinite health/ammo). Or select and press `l` to pre-fill the command bar." },
    { L"unlockentry / u",   L"`unlockentry <index>` -- stop the lock loop on an entry so its value moves freely again. Or select and press `u`." },
    { L"saveentry",         L"`saveentry <filename>` -- persist the table to a human-readable text file with quoted labels and hex addresses." },
    { L"loadentry",         L"`loadentry <filename>` -- restore a saved table. A malformed file fails loudly instead of silently dropping entries." },
    { L"persistence",     L"Entries survive attach/detach cycles. They remain in the table even with no process attached, showing `no process` for values." },
    { L"help / ?",          L"open this help book for the focused panel" },
    { L"quit / exit",       L"close the memory engine" },
};

static const HelpEntry addr_keys_entries[] = {
    { L"Up / Down", L"Move selection cursor through entries" },
    { L"d",         L"Delete the selected entry" },
    { L"l",         L"Lock the selected entry (opens the command bar with `lockentry <index> ` pre-filled)" },
    { L"u",         L"Unlock the selected entry" },
    { L"e",         L"Rename the selected entry (opens the command bar pre-filled)" },
    { L"r",         L"Read the selected entry's address -- opens the command bar pre-filled with `read <addr> ` (type the byte count, 1-512, then Enter)" },
    { L"w",         L"Write to the selected entry's address -- opens the command bar pre-filled with `write <addr> ` (type hex byte pairs, then Enter)" },
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
      addr_manage_entries,   HELP_COUNT(addr_manage_entries) },
    { L"Keys",         L"Keyboard shortcuts active when the address table panel is focused.",
      addr_keys_entries,     HELP_COUNT(addr_keys_entries) },
};

static const HelpBook addr_book = {
    L"Address Table Help", addr_pages, HELP_COUNT(addr_pages)
};

const HelpBook *tui_help_address_table_book(void) { return &addr_book; }