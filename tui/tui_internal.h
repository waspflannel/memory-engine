#ifndef TUI_INTERNAL_H
#define TUI_INTERNAL_H

/*
 * Internal shared surface for the TUI module only. The public TUI API stays in
 * tui.h (tui_init/run/shutdown); this header is what tui.c / commands.c /
 * helpers.c use to reach the tui_state singleton and the few helpers that cross
 * files. Nothing outside app/tui/ includes this.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "core/process/process.h"
#include "core/scanner/scanner.h"
#include "core/address_table/address_table.h"
#include "core/hexview/hexview.h"
#include "tui/help.h"

/* Sizes shared by the tui_state definition (tui.c) and the helpers that touch
   its buffers. Keep these here so the struct field width and the bound checks
   in the helpers stay tied. */
#define CMD_BUF_MAX        256
#define STATUS_MSG_MAX     512
#define MAX_STATUS_TICKS   3000
#define HEXVIEW_WINDOW_MAX 256
#define HEXVIEW_REFRESH_INTERVAL_MS 200

enum { PANEL_PROCESSES, PANEL_SCANNER, PANEL_ADDRTABLE, PANEL_HEXVIEW,
       PANEL_DISASM, PANEL_DEBUGGER, PANEL_SCRIPTS, PANEL_PROFILES,
       PANEL_COUNT };

/* The TUI's module singleton. Defined in tui.c; the draw/input/commands code
   all borrow it. Named (not anonymous) so the extern below can name it. */
typedef struct {
    HANDLE hOut;
    HANDLE hIn;
    int    width;
    int    height;

    int focus;
    int panel;
    int sidebar_idx;

    ProcessEntry *processes;
    unsigned int   process_count;
    unsigned int  *process_view;     /* indexes into `processes` that pass the filter */
    unsigned int   process_view_count;
    wchar_t        process_filter[PROCESS_NAME_MAX]; /* empty == no filter */
    int            selected_process;   /* index into process_view */
    int            process_scroll;

    Target  target;
    int     attached;

    ScanSession scanner;
    int         scanner_inited;
    int         string_enc;

    AddrTable  address_table;
    int        address_table_scroll;
    int        address_table_selected;
    ULONGLONG  address_table_last_refresh;
    ULONGLONG  address_table_last_lock;
    int        scanner_selected_index;

    unsigned long long hexview_address;
    size_t             hexview_cursor;
    size_t             hexview_byte_count;
    unsigned short     hexview_bytes_per_row;
    unsigned char      hexview_bytes[HEXVIEW_WINDOW_MAX];
    unsigned char      hexview_readable[HEXVIEW_WINDOW_MAX];
    MemoryRegion       hexview_first_region;
    ULONGLONG          hexview_last_refresh;
    int                hexview_window_valid;
    int                hexview_high_nibble;

    int             help_open;
    int             help_tab;
    int             help_scroll;
    int             help_more_below;
    const HelpBook *help_book;

    wchar_t cmd_buf[CMD_BUF_MAX];
    int     cmd_len;

    wchar_t   status_msg[STATUS_MSG_MAX];
    int       status_error;
    ULONGLONG status_ticks;

    int running;
} TuiState;

extern TuiState tui_state;

/* helpers.c -- shared app state + scan-value parsing. */
void           tui_set_status(const wchar_t *msg, int is_error);
int            tui_refresh_process_list(void);
void           tui_detach_target(void);
int            tui_do_attach(DWORD pid);
void           tui_attach_to_selected(void);
void           tui_hexview_jump(unsigned long long address);
const wchar_t *tui_scan_type_name(ScanType type);
int            tui_parse_scan_value(const wchar_t *args, ScanValue *out);
int            tui_hex_digit_value(wchar_t c);

/* Process list filtering: list rebuilds `process_view` from `processes` using
   the current `process_filter` substring (case-insensitive). An empty needle
   produces the identity view (every process shown). */
void           tui_set_process_filter(const wchar_t *needle);
DWORD          tui_next_wait_timeout(ULONGLONG now);

/* commands.c -- command palette dispatcher (called from input in tui.c). */
void           tui_exec_command(void);

#endif
