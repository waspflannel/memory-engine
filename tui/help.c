#include "tui/help.h"
#include "tui_internal.h"

const HelpBook *tui_help_book_for_panel(int panel)
{
    if (panel == PANEL_PROCESSES) return &tui_help_processes;
    if (panel == PANEL_SCANNER)   return &tui_help_scanner;
    if (panel == PANEL_ADDRTABLE) return &tui_help_address_table;
    if (panel == PANEL_HEXVIEW)   return &tui_help_hexview;
    if (panel == PANEL_DISASM)    return &tui_help_disasm;
    if (panel == PANEL_DEBUGGER)  return &tui_help_debugger;
    return NULL;
}

int tui_open_help(void)
{
    const HelpBook *book = tui_help_book_for_panel(tui_state.panel);
    if (!book) return 0;
    tui_state.help_book = book;
    tui_state.help_open = 1;
    tui_state.help_tab = 0;
    tui_state.help_scroll = 0;
    return 1;
}
