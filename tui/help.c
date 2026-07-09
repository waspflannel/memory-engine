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
    { L"exact",       L"first or next scan: keep addresses whose current value matches the number you type" },
    { L"changed",     L"next scan only: keep addresses whose value differs from the last snapshotted value" },
    { L"unchanged",   L"next scan only: keep addresses whose value is identical to the last snapshotted value" },
    { L"increased",   L"next scan only: keep addresses whose current value is greater than it was (numeric types only)" },
    { L"decreased",   L"next scan only: keep addresses whose current value is less than it was (numeric types only)" },
    { L"increasedby", L"next scan only: keep addresses where value went up by exactly N (numeric types only, needs a number)" },
    { L"decreasedby", L"next scan only: keep addresses where value went down by exactly N (numeric types only, needs a number)" },
    { L"between",     L"next scan only: keep addresses where lo <= value <= hi (numeric types only, needs two numbers like `next 50 100`)" },
    { L"unknown",     L"first scan only: snapshot every address with whatever value it holds; then narrow with the modes above" },
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
    { L"type <name>",   L"set the value type you are searching for -- clears any current scan results and resets mode to exact" },
    { L"mode <name>",   L"set how the scanner filters results: exact, changed, increased, between, etc. (see Modes tab)" },
    { L"scan <value>",  L"first scan: walk every byte of committed readable memory and keep addresses matching the value; `scan ?` snapshots everything (unknown mode)" },
    { L"next [value]",  L"narrows the current result set using the active mode; value arguments depend on the mode (exact/increasedby/between need them, changed/unchanged don't)" },
    { L"scanclear",     L"drop the current result set and reset -- use this to start a fresh scan from scratch" },
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

const HelpBook *tui_help_book_for_panel(int panel)
{
    if (panel == PANEL_SCANNER) return &scanner_book;
    return NULL;
}
