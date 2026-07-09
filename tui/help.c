#include <wchar.h>
#include "tui/help.h"
#include "tui_internal.h"

#define HELP_COUNT(a) ((int)(sizeof(a) / sizeof((a)[0])))

static const HelpEntry types_entries[] = {
    { L"i8",     L"signed 8-bit integer, -128..127, 1 byte" },
    { L"i16",    L"signed 16-bit integer, 2 bytes" },
    { L"i32",    L"signed 32-bit integer, 4 bytes (default)" },
    { L"i64",    L"signed 64-bit integer, 8 bytes" },
    { L"u8",     L"unsigned 8-bit, 0..255, 1 byte" },
    { L"u16",    L"unsigned 16-bit, 0..65535, 2 bytes" },
    { L"u32",    L"unsigned 32-bit, 4 bytes" },
    { L"u64",    L"unsigned 64-bit, 8 bytes" },
    { L"f32",    L"32-bit IEEE float, 4 bytes" },
    { L"f64",    L"64-bit IEEE double, 8 bytes" },
    { L"string", L"text; byte width set by `strenc` (see Encoding page)" },
    { L"aob",    L"array of bytes; hex pairs with `??` wildcards (see AOB page)" },
};

static const HelpEntry modes_entries[] = {
    { L"exact",       L"keep addresses equal to the value you type (first or next)" },
    { L"changed",     L"next scan: keep values that differ from last scan (no value)" },
    { L"unchanged",   L"next scan: keep values equal to last scan (no value)" },
    { L"increased",   L"next scan: value went up since last scan (numeric, no value)" },
    { L"decreased",   L"next scan: value went down since last scan (numeric, no value)" },
    { L"increasedby", L"next scan: value went up by exactly N (numeric, needs N)" },
    { L"decreasedby", L"next scan: value went down by exactly N (numeric, needs N)" },
    { L"between",     L"next scan: keep lo <= value <= hi (numeric, needs `lo hi`)" },
    { L"unknown",     L"first scan only: snapshot every address, then narrow with the modes above" },
};

static const HelpEntry encodings_entries[] = {
    { L"strenc ascii", L"one byte per character; non-ASCII input is rejected" },
    { L"strenc utf16", L"two bytes per character, little-endian (Windows wide strings)" },
    { L"utf-8",        L"not supported yet (deferred -- see tech-debt tracker)" },
    { L"aob format",   L"space-separated hex byte pairs, e.g. `48 8B ?? ?? 90`" },
    { L"??",           L"wildcard -- matches any byte at that position" },
    { L"raw compare",  L"aob and string match raw bytes; no endianness is applied" },
};

static const HelpEntry workflow_entries[] = {
    { L"the loop",      L"`scan` a value, change it in the game, `next` to narrow; repeat to a few addresses" },
    { L"type <name>",   L"set the value type (clears current results)" },
    { L"mode <name>",   L"set the scan mode" },
    { L"scan <value>",  L"first scan for a value; `scan ?` snapshots all (unknown-initial)" },
    { L"next [value]",  L"narrow current results with the active mode" },
    { L"scanclear",     L"drop the current result set" },
    { L"strenc a|u",    L"set string encoding (ascii or utf16)" },
    { L"help / ?",      L"open this book; Esc closes" },
};

static const HelpPage scanner_pages[] = {
    { L"Types",         L"Value types the scanner can search for.",
      types_entries,      HELP_COUNT(types_entries) },
    { L"Modes",         L"How a scan keeps or drops each address.",
      modes_entries,      HELP_COUNT(modes_entries) },
    { L"Strings & AOB", L"String encodings and array-of-bytes syntax.",
      encodings_entries,  HELP_COUNT(encodings_entries) },
    { L"Workflow",      L"The find-then-narrow loop, and every scanner command.",
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
