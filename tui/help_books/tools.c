#include "tui/help.h"

static const HelpEntry overview[] = {
    { L"Pointers", L"Press P on a selected Scanner or AddrTable value, or use pointers <address>. Finds aligned x64 pointer paths rooted in the main executable. Results are bounded; truncation and unreadable memory are reported." },
    { L"Resolve", L"Up/Down selects a path; Left/Right reveals long paths. R resolves it; Enter opens the destination in Hex View. C cancels scanning. Paths stay in this session across detach. Reattach the same executable and use pointerfilter <new_address>." },
    { L"Structure", L"Press I on a selected value, or use structure <address> [size]. R rereads the window; * marks rows/fields changed since the previous refresh. ?? means unreadable, never zero. Up/Down and Page Up/Down scroll." },
    { L"Fields", L"field <hex_offset> <numeric_type> <label> adds or replaces a typed field. Up to 32 fields within 256 bytes; labels remain in this session until another window opens or you detach." },
    { L"DLL loading", L"inject <path> uses the standard Windows loader in an attached native x64 target. The DLL must also be x64. Completion appears in the status bar. Stop the debugger watch first; wait for loading before detach or quit. Detach does not unload the DLL." },
};
static const HelpPage pages[] = {
    { L"Overview", L"Small tools for memory inspection.", overview, HELP_COUNT(overview) },
    { L"Commands", L"Addresses and field offsets are hexadecimal; sizes and scan limits are decimal.", tui_command_help_entries, TUI_COMMAND_HELP_COUNT },
};
const HelpBook tui_help_tools = { L"Memory Tools Help", pages, HELP_COUNT(pages) };
