#include <wchar.h>
#include "tui/help.h"
#include "tui_internal.h"

#define HELP_COUNT(a) ((int)(sizeof(a) / sizeof((a)[0])))

static const HelpEntry types_entries[] = {
    { L"i8",     L"signed 8-bit integer, range -128 to 127, 1 byte in memory" },
    { L"i16",    L"signed 16-bit integer, range -32768 to 32767, 2 bytes" },
    { L"i32",    L"signed 32-bit integer, ~-2B to +2B, 4 bytes (default type on attach)" },
    { L"i64",    L"signed 64-bit integer, full pointer-width range, 8 bytes" },
    { L"u8",     L"unsigned 8-bit integer, range 0 to 255, 1 byte" },
    { L"u16",    L"unsigned 16-bit integer, range 0 to 65535, 2 bytes" },
    { L"u32",    L"unsigned 32-bit integer, range 0 to ~4B, 4 bytes" },
    { L"u64",    L"unsigned 64-bit integer, wide counter values, 8 bytes" },
    { L"f32",    L"32-bit IEEE 754 float, ~7 digits precision, 4 bytes" },
    { L"f64",    L"64-bit IEEE 754 double, ~15 digits precision, 8 bytes" },
    { L"string", L"variable-length text; set encoding with `strenc` (see Strings & AOB tab)" },
    { L"aob",    L"array of bytes; space-separated hex pairs with `??` wildcards (see Strings & AOB tab)" },
};

static const HelpEntry modes_entries[] = {
    { L"exact", L"first scan: walk every byte of committed readable memory, keep addresses matching the typed value; next scan: re-read surviving addresses, keep those still matching" },
};

static const HelpEntry encodings_entries[] = {
    { L"strenc ascii", L"one byte per character for plain text; non-ASCII characters (>= 128) are rejected on input" },
    { L"strenc utf16", L"two bytes per character, little-endian byte order; this is how Windows stores wide strings internally" },
    { L"utf-8",        L"not yet supported (deferred -- search as raw AOB bytes for now; see tech-debt tracker)" },
    { L"aob format",   L"space-separated hex byte pairs, e.g. `48 8B 10 90` or `48 ?? ?? 90`" },
    { L"??",           L"wildcard placeholder -- matches any byte at that position; only valid in AOB patterns" },
    { L"raw compare",  L"scanner compares raw bytes directly; no endianness conversion is applied -- the bytes you type are the bytes read from memory" },
};

static const HelpEntry workflow_entries[] = {
    { L"the loop",      L"`scan` a value, change it in the game, `next` to narrow; repeat until one address remains" },
    { L"type <name>",   L"set the value type you are searching for -- clears any current scan results" },
    { L"scan <value>",  L"first scan: walk every byte of committed readable memory and keep addresses matching the value" },
    { L"next <value>",  L"re-reads surviving addresses, keeping only those that now match the new value" },
    { L"strenc a|u",    L"set string encoding to ascii or utf16 for the string scan type" },
    { L"help / ?",      L"open this book (press ? on the Scanner panel, or type `help` in the command bar)" },
};

static const HelpPage scanner_pages[] = {
    { L"Types",         L"Value types the scanner can search for -- set with `type <name>`.",
      types_entries,      HELP_COUNT(types_entries) },
    { L"Modes",         L"How the scanner decides to keep or discard each address during filtering.",
      modes_entries,      HELP_COUNT(modes_entries) },
    { L"Strings & AOB", L"String encodings for text scans and array-of-bytes syntax for exact byte matching.",
      encodings_entries,  HELP_COUNT(encodings_entries) },
    { L"Workflow",      L"The find-then-narrow loop, and every scanner command you can type.",
      workflow_entries,   HELP_COUNT(workflow_entries) },
};

static const HelpBook scanner_book = {
    L"Scanner Help", scanner_pages, HELP_COUNT(scanner_pages)
};

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
    { L"addentry",        L"`addentry <hex_addr> <type> <label>` -- add a manual entry. Type is one of i8/i16/i32/i64/u8/u16/u32/u64/f32/f64/string/aob." },
    { L"delentry / d",    L"`delentry <index>` or select and press `d` to remove an entry from the table." },
    { L"entrylabel / e",  L"`entrylabel <index> <new_label>` or select and press `e` to rename an entry." },
    { L"saveentry",       L"`saveentry <filename>` -- persist the table to a file. Format is human-readable text with quoted labels and hex addresses." },
    { L"loadentry",       L"`loadentry <filename>` -- restore a saved table. A malformed file fails loudly instead of silently dropping entries." },
    { L"persistence",     L"Entries survive attach/detach cycles. They remain in the table even with no process attached, showing `no process` for values." },
};

static const HelpEntry addr_keys_entries[] = {
    { L"Up / Down",       L"Move selection cursor through entries" },
    { L"d",               L"Delete the selected entry" },
    { L"l",               L"Lock the selected entry (opens the command bar with `lockentry <index> ` pre-filled)" },
    { L"u",               L"Unlock the selected entry" },
    { L"e",               L"Rename the selected entry (opens the command bar pre-filled)" },
    { L"?",               L"Open this help book" },
    { L"Esc",             L"Return focus to the sidebar panel selector" },
    { L"Tab",             L"Cycle focus between sidebar, panel, and command bar" },
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

const HelpBook *tui_help_book_for_panel(int panel)
{
    if (panel == PANEL_SCANNER)   return &scanner_book;
    if (panel == PANEL_ADDRTABLE) return &addr_book;
    return NULL;
}
