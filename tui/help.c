#include "tui/help.h"
#include "tui_internal.h"

const HelpBook *tui_help_book_for_panel(int panel)
{
    if (panel == PANEL_PROCESSES) return tui_help_processes_book();
    if (panel == PANEL_SCANNER)   return tui_help_scanner_book();
    if (panel == PANEL_ADDRTABLE) return tui_help_address_table_book();
    if (panel == PANEL_HEXVIEW)   return tui_help_hexview_book();
    return NULL;
}
