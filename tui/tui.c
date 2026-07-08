#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

#include "tui/render.h"
#include "tui_internal.h"

#define SIDEBAR_WIDTH   12
#define HEADER_ROW      1
#define SEP1_ROW        2
#define CONTENT_START   3

#define INPUT_RECORD_BATCH 16
#define SCANNER_LIST_ROWS 20  /* max result addresses drawn in the scanner panel */

/* Box-drawing glyphs -- semantic roles, not Unicode code points */
#define BOX_TL     L'\x250C'
#define BOX_TR     L'\x2510'
#define BOX_BL     L'\x2514'
#define BOX_BR     L'\x2518'
#define BOX_H      L'\x2500'
#define BOX_V      L'\x2502'
#define BOX_TLEFT  L'\x251C'
#define BOX_TRIGHT L'\x2524'
#define BOX_TTOP   L'\x252C'

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
static const WORD s_attr_sel    = BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED;
static const WORD s_attr_header = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static const WORD s_attr_border = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static const WORD s_attr_error  = FOREGROUND_RED;

TuiState tui_state;

/* Forward declarations -- definitions at bottom of file. */
static void draw_borders(Screen *screen);
static void draw_sep_row(Screen *screen, int y, int split);
static void draw_header(Screen *screen);
static void draw_sidebar(Screen *screen);
static void draw_process_list(Screen *screen);
static void draw_scanner_panel(Screen *screen);
static void draw_main_panel(Screen *screen);
static void draw_command(Screen *screen);
static void render(void);
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

    tui_refresh_process_list();

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
    swprintf_s(line, _countof(line), L"Scanner -- type: %s  mode: %s  enc: %s",
               tui_scan_type_name(s->param.type), tui_scan_mode_name(s->mode), enc);
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
        unsigned short w = s->results.value_width;
        unsigned short shown_w = w > 16 ? 16 : w;
        for (size_t i = 0; i < s->results.count && i < SCANNER_LIST_ROWS; i++) {
            const unsigned char *val = s->results.values + i * w;
            int p = swprintf_s(addrs, _countof(addrs), L"  0x%016llX  ", s->results.addresses[i]);
            for (unsigned short k = 0; k < shown_w && p + 4 < (int)_countof(addrs); k++) {
                p += swprintf_s(addrs + p, _countof(addrs) - p, L"%02X ", val[k]);
            }
            if (w > 16) {
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
                    L"cmds: type <name>  mode <name>  scan <v>|?  next <v>  scanclear  strenc ascii|utf16",
                    s_attr_border);
    }
}

static void draw_command(Screen *screen)
{
    int cmd_row = tui_state.height - 2;

    wchar_t display[STATUS_MSG_MAX];
    if (tui_state.status_msg[0] && (GetTickCount64() - tui_state.status_ticks) < MAX_STATUS_TICKS) {
        swprintf_s(display, STATUS_MSG_MAX, L" %s", tui_state.status_msg);
        WORD attr = tui_state.status_error ? s_attr_error : s_attr_normal;
        screen_text(screen, 1, cmd_row, display, attr);
    } else {
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
                tui_attach_to_selected();
            } else if (vk == VK_F5) {
                tui_refresh_process_list();
                tui_set_status(L"Process list refreshed", FALSE);
            }
        }
        if (vk == VK_ESCAPE) {
            tui_state.focus = FOCUS_SIDEBAR;
        }
        break;

    case FOCUS_COMMAND:
        if (vk == VK_RETURN) {
            tui_exec_command();
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