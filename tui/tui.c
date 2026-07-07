#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#include "tui/render.h"
#include "core/process/process.h"
#include "core/memory/memory.h"
#include "core/scanner/scanner.h"

#define SIDEBAR_WIDTH   12
#define HEADER_ROW      1
#define SEP1_ROW        2
#define CONTENT_START   3
#define MAX_STATUS_TICKS 3000

/* Box-drawing glyphs — semantic roles, not Unicode code points */
#define BOX_TL     L'\x250C'
#define BOX_TR     L'\x2510'
#define BOX_BL     L'\x2514'
#define BOX_BR     L'\x2518'
#define BOX_H      L'\x2500'
#define BOX_V      L'\x2502'
#define BOX_TLEFT  L'\x251C'
#define BOX_TRIGHT L'\x2524'
#define BOX_TTOP   L'\x252C'

/* Command-prefix lengths, coupled to their literals in exec_command */
#define CMD_ATTACH_PREFIX 7  /* length of L"attach " */
#define CMD_READ_PREFIX   5  /* length of L"read "   */
#define CMD_WRITE_PREFIX  6  /* length of L"write "  */
#define CMD_SCAN_PREFIX   5  /* length of L"scan "   */
#define CMD_NEXT_PREFIX   5  /* length of L"next "   */

#define CMD_BUF_MAX    256
#define STATUS_MSG_MAX 512
#define INPUT_RECORD_BATCH 16
#define SCANNER_LIST_ROWS 20  /* max result addresses drawn in the scanner panel */

enum { FOCUS_SIDEBAR, FOCUS_MAIN, FOCUS_COMMAND };
enum { PANEL_PROCESSES, PANEL_SCANNER, PANEL_ADDRTABLE, PANEL_HEXVIEW,
       PANEL_DISASM, PANEL_DEBUGGER, PANEL_SCRIPTS, PANEL_PROFILES,
       PANEL_COUNT };

static const wchar_t *s_sidebar_labels[PANEL_COUNT] = {
    L"Processes",
    L"Scanner",
    L"AddrTable",
    L"Hex View",
    L"Disasm",
    L"Debugger",
    L"Scripts",
    L"Profiles",
};

static const WORD s_attr_normal = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

static const WORD s_attr_sel = BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED;

static const WORD s_attr_header = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

static const WORD s_attr_border = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

static const WORD s_attr_error = FOREGROUND_RED;

static struct {
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
} tui_state;

/* Forward declarations — definitions at bottom of file. */
static void draw_borders(Screen *screen);
static void draw_sep_row(Screen *screen, int y, int split);
static void draw_header(Screen *screen);
static void draw_sidebar(Screen *screen);
static void draw_process_list(Screen *screen);
static void draw_scanner_panel(Screen *screen);
static void draw_main_panel(Screen *screen);
static void draw_command(Screen *screen);
static void render(void);
static void set_status(const wchar_t *msg, int is_error);
static void refresh_process_list(void);
static int  do_attach(DWORD pid);
static void attach_to_selected(void);
static void cmd_read(const wchar_t *args);
static void cmd_write(const wchar_t *args);
static void cmd_scan(const wchar_t *args);
static void cmd_next(const wchar_t *args);
static void cmd_scanclear(void);
static void cmd_type(const wchar_t *args);
static void cmd_strenc(const wchar_t *args);
static int  parse_scan_value(const wchar_t *args, ScanValue *out);
static int  parse_aob_value(const wchar_t *args, ScanValue *out);
static int  parse_string_value(const wchar_t *args, ScanValue *out);
static const wchar_t *scan_type_name(ScanType type);
static void exec_command(void);
static void handle_key(WORD vk, WCHAR ch);
static void read_input(void);

/* ---- Public API (order matches tui.h) ---- */

int tui_init(void)
{
    tui_state.hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    tui_state.hIn  = GetStdHandle(STD_INPUT_HANDLE);

    if (tui_state.hOut == INVALID_HANDLE_VALUE || tui_state.hIn == INVALID_HANDLE_VALUE) {
        return -1;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi = {0};
    if (!GetConsoleScreenBufferInfo(tui_state.hOut, &csbi)) return -1;
    tui_state.width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    tui_state.height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    if (tui_state.width < 80) tui_state.width = 80;
    if (tui_state.height < 25) tui_state.height = 25;

    CONSOLE_CURSOR_INFO ci = {0};
    GetConsoleCursorInfo(tui_state.hOut, &ci);
    ci.bVisible = FALSE;
    SetConsoleCursorInfo(tui_state.hOut, &ci);

    SetConsoleTitleW(L"MemForge");

    DWORD mode;
    GetConsoleMode(tui_state.hIn, &mode);
    mode &= ~ENABLE_PROCESSED_INPUT;
    mode &= ~ENABLE_LINE_INPUT;
    mode &= ~ENABLE_ECHO_INPUT;
    mode |= ENABLE_WINDOW_INPUT;
    SetConsoleMode(tui_state.hIn, mode);

    tui_state.panel        = PANEL_PROCESSES;
    tui_state.sidebar_idx  = 0;
    tui_state.focus        = FOCUS_SIDEBAR;
    tui_state.running      = TRUE;

    memset(&tui_state.target, 0, sizeof(tui_state.target));
    tui_state.attached = FALSE;
    tui_state.scanner_inited = FALSE;
    tui_state.string_enc = 0;

    refresh_process_list();

    return 0;
}

void tui_run(void)
{
    while (tui_state.running) {
        render();
        read_input();
    }
}

void tui_shutdown(void)
{
    CONSOLE_CURSOR_INFO ci = {0};
    GetConsoleCursorInfo(tui_state.hOut, &ci);
    ci.bVisible = TRUE;
    SetConsoleCursorInfo(tui_state.hOut, &ci);

    DWORD mode;
    GetConsoleMode(tui_state.hIn, &mode);
    mode |= ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
    SetConsoleMode(tui_state.hIn, mode);

    if (tui_state.attached) {
        if (tui_state.scanner_inited) {
            scanner_session_destroy(&tui_state.scanner);
            tui_state.scanner_inited = FALSE;
        }
        process_detach(&tui_state.target);
        tui_state.attached = FALSE;
    }

    if (tui_state.processes) {
        process_free_list(tui_state.processes);
        tui_state.processes = NULL;
    }

    DWORD written;
    COORD zero = {0, 0};
    FillConsoleOutputCharacterW(tui_state.hOut, L' ', (DWORD)(tui_state.width * tui_state.height), zero, &written);
    SetConsoleCursorPosition(tui_state.hOut, zero);
}

/* ---- Static helpers: screen composition ---- */

static void draw_borders(Screen *screen)
{
    WORD attr = s_attr_border;

    screen_put(screen, 0,               0,                       BOX_TL, attr);
    screen_put(screen, tui_state.width - 1, 0,                   BOX_TR, attr);
    screen_put(screen, 0,               tui_state.height - 1,    BOX_BL, attr);
    screen_put(screen, tui_state.width - 1, tui_state.height - 1, BOX_BR, attr);

    screen_fill_row(screen, 0,                BOX_H, attr, 1, tui_state.width - 2);
    screen_fill_row(screen, tui_state.height - 1, BOX_H, attr, 1, tui_state.width - 2);

    for (int y = 1; y < tui_state.height - 1; y++) {
        screen_put(screen, 0,                y, BOX_V, attr);
        screen_put(screen, tui_state.width - 1, y, BOX_V, attr);
    }
}

static void draw_sep_row(Screen *screen, int y, int split)
{
    WORD attr = s_attr_border;
    int sb_end = 1 + SIDEBAR_WIDTH;

    screen_put(screen, 0,                y, BOX_TLEFT,  attr);
    screen_put(screen, tui_state.width - 1, y, BOX_TRIGHT, attr);

    if (split) {
        screen_fill_row(screen, y, BOX_H, attr, 1, sb_end - 1);
        screen_put(screen, sb_end, y, BOX_TTOP, attr);
        screen_fill_row(screen, y, BOX_H, attr, sb_end + 1, tui_state.width - 2);
    } else {
        screen_fill_row(screen, y, BOX_H, attr, 1, tui_state.width - 2);
    }
}

static void draw_header(Screen *screen)
{
    screen_text(screen, 2, HEADER_ROW, L"MemForge v0.1", s_attr_header);

    wchar_t status[PROCESS_NAME_MAX + 32];
    if (tui_state.attached) {
        swprintf_s(status, _countof(status), L"[Process: %s PID:%u]", tui_state.target.name, tui_state.target.pid);
    } else {
        swprintf_s(status, _countof(status), L"[No process attached]");
    }
    screen_text_right(screen, tui_state.width - 2, HEADER_ROW, status, s_attr_header);

    screen_put(screen, 0,                HEADER_ROW, BOX_V, s_attr_border);
    screen_put(screen, tui_state.width - 1, HEADER_ROW, BOX_V, s_attr_border);
}

static void draw_sidebar(Screen *screen)
{
    int sb_end = 1 + SIDEBAR_WIDTH;

    for (int i = 0; i < PANEL_COUNT; i++) {
        int row = CONTENT_START + i;
        if (row >= tui_state.height - 2) break;

        WORD attr;
        if (i == tui_state.sidebar_idx && tui_state.focus == FOCUS_SIDEBAR) {
            attr = s_attr_sel;
        } else {
            attr = s_attr_normal;
        }
        for (int x = 1; x < sb_end; x++) {
            screen_put(screen, x, row, L' ', attr);
        }
        screen_text(screen, 2, row, s_sidebar_labels[i], attr);
    }
}

static void draw_process_list(Screen *screen)
{
    int main_x = 1 + SIDEBAR_WIDTH + 1;
    int main_w = tui_state.width - main_x - 1;
    if (main_w < 10) return;

    int vis_rows = (tui_state.height - 3) - CONTENT_START;
    if (vis_rows <= 0) return;

    int max_scroll = (int)tui_state.process_count - vis_rows;
    if (max_scroll < 0) max_scroll = 0;
    if (tui_state.process_scroll > max_scroll) tui_state.process_scroll = max_scroll;
    if (tui_state.process_scroll < 0) tui_state.process_scroll = 0;

    wchar_t line[PROCESS_NAME_MAX + 16];
    for (int i = 0; i < vis_rows; i++) {
        int pi = tui_state.process_scroll + i;
        int row = CONTENT_START + i;
        if ((unsigned int)pi >= tui_state.process_count) break;

        ProcessEntry *entry = &tui_state.processes[pi];
        swprintf_s(line, _countof(line), L"%5u  %s", entry->pid, entry->name);
        WORD attr;
        if (pi == tui_state.selected_process && tui_state.focus == FOCUS_MAIN) {
            attr = s_attr_sel;
        } else {
            attr = s_attr_normal;
        }
        screen_text(screen, main_x, row, line, attr);
        int used = (int)wcslen(line);
        for (int x = main_x + used; x < tui_state.width - 1; x++) {
            screen_put(screen, x, row, L' ', attr);
        }
    }
}

static void draw_main_panel(Screen *screen)
{
    int sb_end = 1 + SIDEBAR_WIDTH;
    int main_x = sb_end + 1;

    if (tui_state.panel == PANEL_PROCESSES) {
        if (tui_state.process_count > 0) {
            draw_process_list(screen);
        } else {
            screen_text(screen, main_x, CONTENT_START, L"Loading process list...", s_attr_normal);
        }
    } else if (tui_state.panel == PANEL_SCANNER) {
        draw_scanner_panel(screen);
    } else {
        screen_text(screen, main_x, CONTENT_START, L"Not yet implemented", s_attr_normal);
    }
}

static void draw_scanner_panel(Screen *screen)
{
    int sb_end = 1 + SIDEBAR_WIDTH;
    int main_x = sb_end + 1;

    if (!tui_state.attached) {
        screen_text(screen, main_x, CONTENT_START, L"Attach to a process first (Processes panel, or `attach <pid>`)", s_attr_normal);
        return;
    }

    ScanSession *s = &tui_state.scanner;
    wchar_t line[160];
    int row = CONTENT_START;

    const wchar_t *enc = s->param.type == SCAN_TYPE_STRING
        ? (tui_state.string_enc == 1 ? L"utf16" : L"ascii") : L"-";
    swprintf_s(line, _countof(line), L"Scanner -- type: %s  mode: exact  enc: %s",
               scan_type_name(s->param.type), enc);
    screen_text(screen, main_x, row++, line, s_attr_normal);

    /* Hex byte dump of the current param (works for every type). */
    wchar_t hex[160];
    int pos = swprintf_s(hex, _countof(hex), L"value(hex): ");
    unsigned short shown = s->param.width > 16 ? 16 : s->param.width;
    for (unsigned short i = 0; i < shown && pos + 4 < (int)_countof(hex); i++) {
        if (s->param.wild[i]) {
            pos += swprintf_s(hex + pos, _countof(hex) - pos, L"?? ");
        } else {
            pos += swprintf_s(hex + pos, _countof(hex) - pos, L"%02X ", s->param.bytes[i]);
        }
    }
    if (s->param.width > 16) {
        pos += swprintf_s(hex + pos, _countof(hex) - pos, L"...");
    }
    swprintf_s(line, _countof(line), L"%s  results: %llu", hex, (unsigned long long)s->results.count);
    screen_text(screen, main_x, row++, line, s_attr_normal);

    row++;  /* blank separator */

    if (!s->has_results) {
        screen_text(screen, main_x, row, L"Run `scan <value>` to find (use `type <name>` to pick type)", s_attr_normal);
    } else if (s->results.count == 0) {
        screen_text(screen, main_x, row, L"No survivors -- try a different value or `scanclear`", s_attr_error);
    } else {
        wchar_t addrs[160];
        for (size_t i = 0; i < s->results.count && i < SCANNER_LIST_ROWS; i++) {
            ScanHit *hit = &s->results.hits[i];
            int p = swprintf_s(addrs, _countof(addrs), L"  0x%016llX  ", hit->address);
            unsigned short w = s->param.width > 16 ? 16 : s->param.width;
            for (unsigned short k = 0; k < w && p + 4 < (int)_countof(addrs); k++) {
                p += swprintf_s(addrs + p, _countof(addrs) - p, L"%02X ", hit->value[k]);
            }
            if (s->param.width > 16) {
                p += swprintf_s(addrs + p, _countof(addrs) - p, L"...");
            }
            screen_text(screen, main_x, row++, addrs, s_attr_normal);
        }
        if (s->results.count > SCANNER_LIST_ROWS) {
            swprintf_s(addrs, _countof(addrs), L"  ... (%llu more)",
                       (unsigned long long)(s->results.count - SCANNER_LIST_ROWS));
            screen_text(screen, main_x, row++, addrs, s_attr_border);
        }
    }

    int help_row = tui_state.height - 4;
    if (help_row > row) {
        screen_text(screen, main_x, help_row,
                    L"commands: type <name>  scan <value>  next <value>  scanclear  strenc ascii|utf16",
                    s_attr_border);
    }
}

static void draw_command(Screen *screen)
{
    int cmd_row = tui_state.height - 2;

    wchar_t display[STATUS_MSG_MAX];
    if (tui_state.status_msg[0] && (GetTickCount64() - tui_state.status_ticks) < MAX_STATUS_TICKS) {
        swprintf_s(display, STATUS_MSG_MAX, L" %s", tui_state.status_msg); //set display to error message
        WORD attr = tui_state.status_error ? s_attr_error : s_attr_normal; // get right styling
        screen_text(screen, 1, cmd_row, display, attr); //display message with right styling
    } else {
		// if no status message or expired, display the command buffer
        swprintf_s(display, STATUS_MSG_MAX, L" > %s", tui_state.cmd_buf);
        WORD attr;
        if (tui_state.focus == FOCUS_COMMAND) {
            attr = s_attr_sel;
        } else {
            attr = s_attr_normal;
        }
        screen_text(screen, 1, cmd_row, display, attr);
    }
}

static void render(void)
{
    Screen screen;
    if (screen_alloc(&screen, tui_state.width, tui_state.height) != 0) return;

    screen_clear(&screen, s_attr_normal);
    draw_borders(&screen);
    draw_sep_row(&screen, SEP1_ROW, TRUE);
    draw_sep_row(&screen, tui_state.height - 3, FALSE);
    draw_header(&screen);
    draw_sidebar(&screen);
    draw_main_panel(&screen);
    draw_command(&screen);

    screen_present(&screen, tui_state.hOut);
    screen_free(&screen);
}

/* ---- Static helpers: app state + actions ---- */

static void set_status(const wchar_t *msg, int is_error)
{
    wcsncpy_s(tui_state.status_msg, STATUS_MSG_MAX, msg, _TRUNCATE);
    tui_state.status_error = is_error;
    tui_state.status_ticks = GetTickCount64();
}

static void refresh_process_list(void)
{
    if (tui_state.processes) {
        process_free_list(tui_state.processes);
        tui_state.processes = NULL;
    }
    tui_state.process_count = 0;
    tui_state.selected_process   = 0;
    tui_state.process_scroll = 0;

    PlatformError err = process_list(&tui_state.processes, &tui_state.process_count);
    if (err != PLATFORM_OK) {
        set_status(L"Failed to list processes", TRUE);
    }
}

static int do_attach(DWORD pid)
{
    if (tui_state.attached) {
        if (tui_state.scanner_inited) {
            scanner_session_destroy(&tui_state.scanner);
            tui_state.scanner_inited = FALSE;
        }
        process_detach(&tui_state.target);
        tui_state.attached = FALSE;
    }

    process_enable_privilege();

    PlatformError err = process_attach(pid, &tui_state.target);
    if (err != PLATFORM_OK) {
        wchar_t msg[512];
        swprintf_s(msg, _countof(msg), L"Failed to attach to PID %u: %S", pid, process_error_string(err));
        set_status(msg, TRUE);
        return 0;
    }

    tui_state.attached = TRUE;
    scanner_session_init(&tui_state.scanner, &tui_state.target, SCAN_TYPE_I32, SCAN_MODE_EXACT);
    tui_state.scanner_inited = TRUE;
    wchar_t msg[PROCESS_NAME_MAX + 32];
    swprintf_s(msg, _countof(msg), L"Attached to %s (PID %u)", tui_state.target.name, pid);
    set_status(msg, FALSE);
    return 1;
}

static void attach_to_selected(void)
{
    if (!tui_state.processes || tui_state.process_count == 0) return;
    if ((unsigned int)tui_state.selected_process >= tui_state.process_count) return;

    do_attach(tui_state.processes[tui_state.selected_process].pid);
}

static void cmd_read(const wchar_t *args)
{
    if (!tui_state.attached) {
        set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    int size = 0;
    if (swscanf_s(args, L"%llx %d", &address, &size) != 2 || size <= 0 || size > 512) {
        set_status(L"usage: read <hex_address> <size_in_bytes>", TRUE);
        return;
    }

    unsigned char buf[512];
    PlatformError err = memory_read(&tui_state.target, address, buf, (size_t)size);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"read failed: %S", process_error_string(err));
        set_status(msg, TRUE);
        return;
    }

    wchar_t result[512];
    int pos = 0;
    for (int i = 0; i < size && pos < 500; i++) {
        pos += swprintf_s(result + pos, 512 - pos, L"%02X ", buf[i]);
    }
    set_status(result, FALSE);
}

static void cmd_write(const wchar_t *args)
{
    if (!tui_state.attached) {
        set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    wchar_t hex[256] = {0};
    if (swscanf_s(args, L"%llx %s", &address, hex, (unsigned int)(sizeof(hex) / sizeof(wchar_t))) != 2) {
        set_status(L"usage: write <hex_address> <hex_bytes>", TRUE);
        return;
    }

    unsigned char buf[128];
    int hex_len = (int)wcslen(hex);
    int byte_count = hex_len / 2;
    if (byte_count == 0 || byte_count > 128 || hex_len % 2 != 0) {
        set_status(L"invalid hex string — even number of hex chars required", TRUE);
        return;
    }

    for (int i = 0; i < hex_len; i++) {
        wchar_t c = hex[i];
        if (!((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f'))) {
            set_status(L"invalid hex string — non-hex characters found", TRUE);
            return;
        }
    }

    for (int i = 0; i < byte_count; i++) {
        swscanf_s(hex + (i * 2), L"%2hhx", &buf[i]);
    }

    PlatformError err = memory_write(&tui_state.target, address, buf, (size_t)byte_count);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"write failed: %S", process_error_string(err));
        set_status(msg, TRUE);
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, _countof(msg), L"Wrote %d byte(s) to 0x%llX", byte_count, address);
    set_status(msg, FALSE);
}

static void cmd_scan(const wchar_t *args)
{
    if (!tui_state.attached || !tui_state.scanner_inited) {
        set_status(L"No process attached", TRUE);
        return;
    }

    if (!parse_scan_value(args, &tui_state.scanner.param)) {
        set_status(L"usage: scan <value>  (could not parse for current type)", TRUE);
        return;
    }

    PlatformError err = scanner_first_scan(&tui_state.scanner);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"first scan failed: %S", process_error_string(err));
        set_status(msg, TRUE);
        return;
    }

    wchar_t msg[128];
    swprintf_s(msg, _countof(msg), L"First scan: %llu matches", (unsigned long long)tui_state.scanner.results.count);
    set_status(msg, FALSE);
}

static void cmd_next(const wchar_t *args)
{
    if (!tui_state.attached || !tui_state.scanner_inited) {
        set_status(L"No process attached", TRUE);
        return;
    }
    if (!tui_state.scanner.has_results) {
        set_status(L"Run `scan <value>` first", TRUE);
        return;
    }

    if (!parse_scan_value(args, &tui_state.scanner.param)) {
        set_status(L"usage: next <value>  (could not parse for current type)", TRUE);
        return;
    }

    PlatformError err = scanner_next_scan(&tui_state.scanner);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"next scan failed: %S", process_error_string(err));
        set_status(msg, TRUE);
        return;
    }

    wchar_t msg[128];
    swprintf_s(msg, _countof(msg), L"Next scan: %llu survivors", (unsigned long long)tui_state.scanner.results.count);
    set_status(msg, FALSE);
}

static void cmd_scanclear(void)
{
    if (!tui_state.scanner_inited) return;
    scan_results_clear(&tui_state.scanner.results);
    tui_state.scanner.has_results = 0;
    set_status(L"Scanner cleared", FALSE);
}

static void cmd_type(const wchar_t *args)
{
    if (!tui_state.attached || !tui_state.scanner_inited) {
        set_status(L"No process attached", TRUE);
        return;
    }

    ScanType type;
    if (wcscmp(args, L"i32") == 0)         type = SCAN_TYPE_I32;
    else if (wcscmp(args, L"i8") == 0)     type = SCAN_TYPE_I8;
    else if (wcscmp(args, L"i16") == 0)    type = SCAN_TYPE_I16;
    else if (wcscmp(args, L"i64") == 0)    type = SCAN_TYPE_I64;
    else if (wcscmp(args, L"u8") == 0)     type = SCAN_TYPE_U8;
    else if (wcscmp(args, L"u16") == 0)    type = SCAN_TYPE_U16;
    else if (wcscmp(args, L"u32") == 0)    type = SCAN_TYPE_U32;
    else if (wcscmp(args, L"u64") == 0)    type = SCAN_TYPE_U64;
    else if (wcscmp(args, L"f32") == 0)    type = SCAN_TYPE_F32;
    else if (wcscmp(args, L"f64") == 0)    type = SCAN_TYPE_F64;
    else if (wcscmp(args, L"string") == 0) type = SCAN_TYPE_STRING;
    else if (wcscmp(args, L"aob") == 0)    type = SCAN_TYPE_AOB;
    else {
        set_status(L"usage: type i8|i16|i32|i64|u8|u16|u32|u64|f32|f64|string|aob", TRUE);
        return;
    }

    /* Re-init the session (drops any prior result set) but keep the same mode.
       The borrowed target pointer is the same field in tui_state, so keep it. */
    scanner_session_init(&tui_state.scanner, &tui_state.target, type, SCAN_MODE_EXACT);

    wchar_t msg[64];
    swprintf_s(msg, _countof(msg), L"Type: %s", scan_type_name(type));
    set_status(msg, FALSE);
}

static void cmd_strenc(const wchar_t *args)
{
    if (wcscmp(args, L"ascii") == 0) {
        tui_state.string_enc = 0;
        set_status(L"String encoding: ASCII", FALSE);
    } else if (wcscmp(args, L"utf16") == 0) {
        tui_state.string_enc = 1;
        set_status(L"String encoding: UTF-16LE", FALSE);
    } else {
        set_status(L"usage: strenc ascii|utf16", TRUE);
    }
}

static void exec_command(void)
{
    if (tui_state.cmd_len == 0) return;

    if (wcscmp(tui_state.cmd_buf, L"quit") == 0 || wcscmp(tui_state.cmd_buf, L"exit") == 0) {
        tui_state.running = FALSE;
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"attach ", CMD_ATTACH_PREFIX) == 0) {
        DWORD pid = (DWORD)_wtol(tui_state.cmd_buf + CMD_ATTACH_PREFIX);
        if (pid == 0) {
            set_status(L"Invalid PID", TRUE);
        } else {
            do_attach(pid);
        }
        tui_state.cmd_len = 0;
        return;
    }

    if (wcscmp(tui_state.cmd_buf, L"detach") == 0) {
        if (tui_state.attached) {
            process_detach(&tui_state.target);
            tui_state.attached = FALSE;
            set_status(L"Detached", FALSE);
        } else {
            set_status(L"No process attached", TRUE);
        }
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"read ", CMD_READ_PREFIX) == 0) {
        cmd_read(tui_state.cmd_buf + CMD_READ_PREFIX);
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"write ", CMD_WRITE_PREFIX) == 0) {
        cmd_write(tui_state.cmd_buf + CMD_WRITE_PREFIX);
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"scan ", CMD_SCAN_PREFIX) == 0) {
        cmd_scan(tui_state.cmd_buf + CMD_SCAN_PREFIX);
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"next ", CMD_NEXT_PREFIX) == 0) {
        cmd_next(tui_state.cmd_buf + CMD_NEXT_PREFIX);
        tui_state.cmd_len = 0;
        return;
    }

    if (wcscmp(tui_state.cmd_buf, L"scanclear") == 0) {
        cmd_scanclear();
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"type ", 5) == 0) {
        cmd_type(tui_state.cmd_buf + 5);
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"strenc ", 7) == 0) {
        cmd_strenc(tui_state.cmd_buf + 7);
        tui_state.cmd_len = 0;
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, _countof(msg), L"Unknown command: %s", tui_state.cmd_buf);
    set_status(msg, TRUE);
    tui_state.cmd_len = 0;
}

/* ---- Static helpers: input ---- */

static void handle_key(WORD vk, WCHAR ch)
{
    switch (tui_state.focus) {
    case FOCUS_SIDEBAR:
        if (vk == VK_UP && tui_state.sidebar_idx > 0) {
            tui_state.sidebar_idx--;
        } else if (vk == VK_DOWN && tui_state.sidebar_idx < PANEL_COUNT - 1) {
            tui_state.sidebar_idx++;
        } else if (vk == VK_RETURN) {
            tui_state.panel = tui_state.sidebar_idx;
            tui_state.focus = FOCUS_MAIN;
        } else if (ch == L'q' || ch == L'Q') {
            tui_state.running = FALSE;
        }
        break;

    case FOCUS_MAIN:
        if (tui_state.panel == PANEL_PROCESSES) {
            if (vk == VK_UP && tui_state.selected_process > 0) {
                tui_state.selected_process--;
                if (tui_state.selected_process < tui_state.process_scroll) tui_state.process_scroll = tui_state.selected_process;
            } else if (vk == VK_DOWN && (unsigned int)tui_state.selected_process + 1 < tui_state.process_count) {
                tui_state.selected_process++;
                int vis_rows = (tui_state.height - 3) - CONTENT_START;
                if (tui_state.selected_process >= tui_state.process_scroll + vis_rows) tui_state.process_scroll = tui_state.selected_process - vis_rows + 1;
            } else if (vk == VK_RETURN) {
                attach_to_selected();
            } else if (vk == VK_F5) {
                refresh_process_list();
                set_status(L"Process list refreshed", FALSE);
            }
        }
        if (vk == VK_ESCAPE) {
            tui_state.focus = FOCUS_SIDEBAR;
        }
        break;

    case FOCUS_COMMAND:
        if (vk == VK_RETURN) {
            exec_command();
        } else if (vk == VK_BACK) {
            if (tui_state.cmd_len > 0) tui_state.cmd_buf[--tui_state.cmd_len] = L'\0';
        } else if (vk == VK_ESCAPE) {
            tui_state.cmd_len = 0;
            tui_state.focus = FOCUS_SIDEBAR;
        } else if (ch >= L' ' && tui_state.cmd_len < CMD_BUF_MAX - 1) {
            tui_state.cmd_buf[tui_state.cmd_len++] = ch;
            tui_state.cmd_buf[tui_state.cmd_len] = L'\0';
        }
        break;
    }

    if (vk == VK_TAB) {
        tui_state.focus = (tui_state.focus + 1) % 3;
    }
}

static void read_input(void)
{
    INPUT_RECORD records[INPUT_RECORD_BATCH];
    DWORD count = 0;
    if (!ReadConsoleInputW(tui_state.hIn, records, INPUT_RECORD_BATCH, &count)) return;

    for (DWORD i = 0; i < count; i++) {
        if (records[i].EventType != KEY_EVENT) continue;
        if (!records[i].Event.KeyEvent.bKeyDown) continue;
        handle_key(records[i].Event.KeyEvent.wVirtualKeyCode,
                   records[i].Event.KeyEvent.uChar.UnicodeChar);
    }
}

/* ---- Static helpers: scan value parsing ---- */

static const wchar_t *scan_type_name(ScanType type)
{
    switch (type) {
    case SCAN_TYPE_I32:    return L"i32";
    case SCAN_TYPE_I8:     return L"i8";
    case SCAN_TYPE_I16:    return L"i16";
    case SCAN_TYPE_I64:    return L"i64";
    case SCAN_TYPE_U8:     return L"u8";
    case SCAN_TYPE_U16:    return L"u16";
    case SCAN_TYPE_U32:    return L"u32";
    case SCAN_TYPE_U64:    return L"u64";
    case SCAN_TYPE_F32:    return L"f32";
    case SCAN_TYPE_F64:    return L"f64";
    case SCAN_TYPE_STRING: return L"string";
    case SCAN_TYPE_AOB:    return L"aob";
    default:               return L"?";
    }
}

static int is_hex_wchar(wchar_t c)
{
    return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f');
}

static int hex_wchar_value(wchar_t c)
{
    if (c >= L'0' && c <= L'9') return (int)(c - L'0');
    if (c >= L'A' && c <= L'F') return (int)(c - L'A') + 10;
    return (int)(c - L'a') + 10;
}

static int parse_aob_value(const wchar_t *args, ScanValue *out)
{
    unsigned char bytes[SCAN_VALUE_MAX];
    unsigned char wild[SCAN_VALUE_MAX];
    size_t n = 0;

    const wchar_t *p = args;
    while (*p) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;

        if (n >= SCAN_VALUE_MAX) return 0;

        if (p[0] == L'?' && p[1] == L'?') {
            wild[n] = 1;
            bytes[n] = 0;
            n++;
            p += 2;
        } else if (is_hex_wchar(p[0]) && is_hex_wchar(p[1])) {
            wild[n] = 0;
            bytes[n] = (unsigned char)((hex_wchar_value(p[0]) << 4) | hex_wchar_value(p[1]));
            n++;
            p += 2;
        } else {
            return 0;   /* malformed token */
        }
    }

    if (n == 0) return 0;

    scanner_value_set(out, SCAN_TYPE_AOB, bytes, n);
    scanner_value_set_wildcard(out, wild, n);
    return 1;
}

static int parse_string_value(const wchar_t *args, ScanValue *out)
{
    size_t len = wcslen(args);
    if (len == 0) return 0;

    unsigned char bytes[SCAN_VALUE_MAX * 2];
    size_t n = 0;

    if (tui_state.string_enc == 1) {
        if (len > SCAN_VALUE_MAX / 2) return 0;
        for (size_t i = 0; i < len; i++) {
            bytes[n++] = (unsigned char)(args[i] & 0xFF);
            bytes[n++] = (unsigned char)((args[i] >> 8) & 0xFF);
        }
    } else {
        if (len > SCAN_VALUE_MAX) return 0;
        for (size_t i = 0; i < len; i++) {
            if (args[i] >= 128) return 0;   /* non-ASCII rejected in ASCII mode */
            bytes[n++] = (unsigned char)args[i];
        }
    }

    scanner_value_set(out, SCAN_TYPE_STRING, bytes, n);
    return 1;
}

static int parse_scan_value(const wchar_t *args, ScanValue *out)
{
    switch (out->type) {
    case SCAN_TYPE_I8:
    case SCAN_TYPE_I16:
    case SCAN_TYPE_I32: {
        int x = 0;
        if (swscanf_s(args, L"%d", &x) != 1) return 0;
        if (out->type == SCAN_TYPE_I8)  { signed char t = (signed char)x;  scanner_value_set(out, out->type, &t, 1); }
        else if (out->type == SCAN_TYPE_I16) { short t = (short)x;        scanner_value_set(out, out->type, &t, 2); }
        else                                { int t = x;                    scanner_value_set(out, out->type, &t, 4); }
        return 1;
    }
    case SCAN_TYPE_I64: {
        long long x = 0;
        if (swscanf_s(args, L"%lld", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_U8:
    case SCAN_TYPE_U16:
    case SCAN_TYPE_U32: {
        unsigned int x = 0;
        if (swscanf_s(args, L"%u", &x) != 1) return 0;
        if (out->type == SCAN_TYPE_U8) { unsigned char t = (unsigned char)x;  scanner_value_set(out, out->type, &t, 1); }
        else if (out->type == SCAN_TYPE_U16) { unsigned short t = (unsigned short)x; scanner_value_set(out, out->type, &t, 2); }
        else                                { unsigned int t = x;             scanner_value_set(out, out->type, &t, 4); }
        return 1;
    }
    case SCAN_TYPE_U64: {
        unsigned long long x = 0;
        if (swscanf_s(args, L"%llu", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_F32: {
        float x = 0.0f;
        if (swscanf_s(args, L"%f", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_F64: {
        double x = 0.0;
        if (swscanf_s(args, L"%lf", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_STRING: return parse_string_value(args, out);
    case SCAN_TYPE_AOB:    return parse_aob_value(args, out);
    default:               return 0;
    }
}