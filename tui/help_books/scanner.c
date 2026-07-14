#include "tui/help.h"

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
    { L"strenc ascii|utf16", L"set string encoding for the string scan type" },
    { L"help / ?",      L"open this book (press ? on the Scanner panel, or type `help` in the command bar)" },
    { L"next steps",    L"when you've narrowed down to your targeted memory address, view the Commands tab to see what you can do" },
};

static const HelpEntry scanner_keys_entries[] = {
    { L"Up / Down", L"Move selection cursor through scan results" },
    { L"r",        L"Read the selected address -- opens the command bar pre-filled with `read <addr> ` (type the byte count, 1-128, then Enter)" },
    { L"w",        L"Write to the selected address -- opens the command bar pre-filled with `write <addr> ` (type hex byte pairs, then Enter)" },
    { L"a",        L"Promote the selected hit to the address table -- opens the command bar pre-filled with `addentry <addr> <type> ` (type a label, then Enter)" },
    { L"?",        L"Open this help book" },
    { L"Esc",      L"Return focus to the sidebar panel selector" },
    { L"Tab",      L"Cycle focus between sidebar, panel, and command bar" },
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
    { L"Commands",      L"Every command you can type in the command bar -- attach/scan/narrow, then read/write/lock once you've found your target.",
      tui_command_help_entries, TUI_COMMAND_HELP_COUNT },
    { L"Keys",          L"Keyboard shortcuts active when the Scanner panel is focused and a hit is selected.",
      scanner_keys_entries,     HELP_COUNT(scanner_keys_entries) },
};

static const HelpBook scanner_book = {
    L"Scanner Help", scanner_pages, HELP_COUNT(scanner_pages)
};

const HelpBook *tui_help_scanner_book(void) { return &scanner_book; }
