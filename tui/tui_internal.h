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

/* Sizes shared by the tui_state definition (tui.c) and the helpers that touch
   its buffers. Keep these here so the struct field width and the bound checks
   in the helpers stay tied. */
#define CMD_BUF_MAX        256
#define STATUS_MSG_MAX     512
#define MAX_STATUS_TICKS   3000

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
    int            selected_process;
    int            process_scroll;

    Target  target;
    int     attached;

    ScanSession scanner;
    int         scanner_inited;
    int         string_enc;       /* SCAN_TYPE_STRING encoding: 0 = ASCII, 1 = UTF-16LE */

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
void           tui_refresh_process_list(void);
int            tui_do_attach(DWORD pid);
void           tui_attach_to_selected(void);
const wchar_t *tui_scan_type_name(ScanType type);
const wchar_t *tui_scan_mode_name(ScanMode mode);
int            tui_parse_scan_value(const wchar_t *args, ScanValue *out);
int            tui_parse_two_numeric(const wchar_t *args, ScanType type, ScanValue *lo, ScanValue *hi);

/* commands.c -- command palette dispatcher (called from input in tui.c). */
void           tui_exec_command(void);

#endif