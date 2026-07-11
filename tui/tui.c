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
#define SCANNER_LIST_ROWS 20
#define ADDR_TABLE_LIST_ROWS 20

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

static const WORD s_attr_help_head =
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

TuiState tui_state;

/* Forward declarations -- definitions at bottom of file. */
static void draw_borders(Screen *screen);
static void draw_sep_row(Screen *screen, int y, int split);
static void draw_header(Screen *screen);
static void draw_sidebar(Screen *screen);
static void draw_process_list(Screen *screen);
static void draw_scanner_panel(Screen *screen);
static void draw_address_table_panel(Screen *screen);
static void draw_main_panel(Screen *screen);
static void draw_command(Screen *screen);
static void draw_help(Screen *screen);
static int  draw_wrapped(Screen *screen, int x, int y, int max_w, const wchar_t *text, WORD attr, int max_rows);
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

    addr_table_init(&tui_state.address_table, NULL);
    tui_state.address_table_scroll = 0;
    tui_state.address_table_selected = 0;
    tui_state.address_table_last_refresh = 0;
    tui_state.address_table_last_lock = 0;
    tui_state.scanner_selected_index = 0;

    tui_state.help_open = 0;
    tui_state.help_tab = 0;
    tui_state.help_scroll = 0;
    tui_state.help_more_below = 0;
    tui_state.help_book = NULL;

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

    addr_table_destroy(&tui_state.address_table);

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
    if (tui_state.help_open) {
        draw_help(screen);
        return;
    }

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
    } else if (tui_state.panel == PANEL_ADDRTABLE) {
        draw_address_table_panel(screen);
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
        screen_text(screen, main_x, row, L"No survivors -- try a different value or run `scan` again", s_attr_error);
    } else {
        if ((size_t)tui_state.scanner_selected_index >= s->results.count) {
            tui_state.scanner_selected_index = s->results.count > 0 ? (int)(s->results.count - 1) : 0;
        }

        int vis_rows = (tui_state.height - 3) - CONTENT_START - 2;
        if (vis_rows <= 0) vis_rows = 1;
        if (vis_rows > (int)SCANNER_LIST_ROWS) vis_rows = (int)SCANNER_LIST_ROWS;

        int scroll = 0;
        int max_scroll = (int)s->results.count - vis_rows;
        if (max_scroll < 0) max_scroll = 0;
        if (tui_state.scanner_selected_index >= scroll + vis_rows) {
            scroll = tui_state.scanner_selected_index - vis_rows + 1;
            if (scroll > max_scroll) scroll = max_scroll;
        } else if (tui_state.scanner_selected_index < scroll) {
            scroll = tui_state.scanner_selected_index;
        }

        wchar_t addrs[160];
        unsigned short w = s->results.value_width;
        unsigned short shown_w = w > 16 ? 16 : w;
        for (size_t i = (size_t)scroll; i < s->results.count && (int)i - scroll < vis_rows; i++) {
            const unsigned char *val = s->results.values + i * w;
            int is_sel = ((int)i == tui_state.scanner_selected_index && tui_state.focus == FOCUS_MAIN);
            WORD attr = is_sel ? s_attr_sel : s_attr_normal;
            int p = swprintf_s(addrs, _countof(addrs), L"  0x%016llX  ", s->results.addresses[i]);
            for (unsigned short k = 0; k < shown_w && p + 4 < (int)_countof(addrs); k++) {
                p += swprintf_s(addrs + p, _countof(addrs) - p, L"%02X ", val[k]);
            }
            if (w > 16) {
                p += swprintf_s(addrs + p, _countof(addrs) - p, L"...");
            }
            screen_text(screen, main_x, row++, addrs, attr);
        }
        if (s->results.count > (size_t)vis_rows) {
            if ((int)s->results.count - scroll > vis_rows) {
                swprintf_s(addrs, _countof(addrs), L"  ... (%llu more)",
                           (unsigned long long)(s->results.count - (size_t)scroll - (size_t)vis_rows));
                screen_text(screen, main_x, row++, addrs, s_attr_border);
            }
        }
    }

    int help_row = tui_state.height - 4;
    if (help_row > row) {
        screen_text(screen, main_x, help_row,
                    L"Up/Dn select  a addentry  ? help   type <name>  scan <v>  next <v>",
                    s_attr_border);
    }
}

static void draw_address_table_panel(Screen *screen)
{
    int sb_end = 1 + SIDEBAR_WIDTH;
    int main_x = sb_end + 1;
    int main_w = tui_state.width - main_x - 1;
    if (main_w < 10) return;

    AddrTable *table = &tui_state.address_table;

    if (!tui_state.attached && table->count == 0) {
        screen_text(screen, main_x, CONTENT_START, L"Attach to a process first to add addresses", s_attr_normal);
    } else if (tui_state.attached && table->count == 0) {
        screen_text(screen, main_x, CONTENT_START,
                    L"No saved addresses -- use `addentry <addr> <type> <label>`,", s_attr_normal);
        screen_text(screen, main_x, CONTENT_START + 1,
                    L"or press `a` on a scanner hit to promote it.", s_attr_normal);
    }

    int vis_rows = (tui_state.height - 3) - CONTENT_START;
    if (vis_rows <= 0) return;

    int max_scroll = (int)table->count - vis_rows;
    if (max_scroll < 0) max_scroll = 0;
    if (tui_state.address_table_scroll > max_scroll) tui_state.address_table_scroll = max_scroll;
    if (tui_state.address_table_scroll < 0) tui_state.address_table_scroll = 0;

    for (int i = 0; i < vis_rows; i++) {
        int ei = tui_state.address_table_scroll + i;
        int row = CONTENT_START + i;
        if ((size_t)ei >= table->count) break;

        const AddrEntry *entry = &table->entries[ei];
        int is_sel = (ei == tui_state.address_table_selected && tui_state.focus == FOCUS_MAIN);
        WORD attr = is_sel ? s_attr_sel : s_attr_normal;

        const wchar_t *lock_char = entry->locked ? L"L" : L" ";
        const wchar_t *value_str = L"?";

        wchar_t val_buf[64];
        if (!entry->value_valid) {
            if (!tui_state.attached) {
                value_str = L"no process";
            } else if (entry->value_width == 0) {
                value_str = L"var";
            } else {
                value_str = L"err";
            }
        } else {
            int pos = 0;
            for (unsigned short k = 0; k < entry->value_width && pos < 45; k++) {
                pos += swprintf_s(val_buf + pos, _countof(val_buf) - pos,
                                  L"%02X ", entry->current_value[k]);
            }
            value_str = val_buf;
        }

        wchar_t line[256];
        const wchar_t *type_name = tui_scan_type_name(entry->type);
        swprintf_s(line, _countof(line), L" [%s] %-20S  %-6s  0x%llX  %s",
                   lock_char, entry->label, type_name,
                   (unsigned long long)entry->address, value_str);

        screen_text(screen, main_x, row, line, attr);
        int used = (int)wcslen(line);
        for (int x = main_x + used; x < tui_state.width - 1; x++) {
            screen_put(screen, x, row, L' ', attr);
        }
    }

    int help_row = tui_state.height - 4;
    if (help_row > CONTENT_START) {
        screen_text(screen, main_x, help_row,
                    L"d del   l lock   u unlock   e label   addentry <addr> <type> <name>",
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

/* Advance past exactly one wrapped line of `text` at `max_w` columns and return
   the start of the next line. Breaks after the last space that fits; hard-splits
   a single word longer than max_w. */
static const wchar_t *wrap_advance(const wchar_t *p, int max_w)
{
    const wchar_t *end = p;
    const wchar_t *last_space = NULL;
    int len = 0;
    while (*end && len < max_w) {
        if (*end == L' ') last_space = end;
        end++;
        len++;
    }
    if (len >= max_w && *end && *end != L' ' && last_space) {
        end = last_space + 1;
    }
    if (end <= p) end = p + (int)wcslen(p);
    return end;
}

/* Number of lines `text` wraps to at `max_w` columns (at least 1). */
static int wrapped_rows(const wchar_t *text, int max_w)
{
    int rows = 0;
    for (const wchar_t *p = text; *p; p = wrap_advance(p, max_w)) rows++;
    return rows > 0 ? rows : 1;
}

static int draw_wrapped(Screen *screen, int x, int y, int max_w, const wchar_t *text, WORD attr, int max_rows)
{
    int rows = 0;
    const wchar_t *p = text;
    while (*p && rows < max_rows) {
        const wchar_t *end = wrap_advance(p, max_w);
        int n = (int)(end - p);
        wchar_t line[256];
        int copy = n < (int)_countof(line) - 1 ? n : (int)_countof(line) - 1;
        wcsncpy_s(line, _countof(line), p, copy);
        line[copy] = L'\0';
        screen_text(screen, x, y + rows, line, attr);
        p = end;
        rows++;
    }
    return rows;
}

static void draw_help(Screen *screen)
{
    const HelpBook *book = tui_state.help_book;
    if (!book) return;

    int x0 = 1 + SIDEBAR_WIDTH + 1;
    int x1 = tui_state.width - 2;
    int y0 = CONTENT_START;
    int y1 = tui_state.height - 4;

    int ix0 = x0 + 2;
    int ix1 = x1 - 2;
    int iw  = ix1 - ix0 + 1;
    int iy0 = y0 + 1;
    int iy1 = y1 - 1;

    int visible_rows = (iy1 - 2) - (iy0 + 4) + 1;
    if (iw < 40 || visible_rows < 3) {
        screen_text(screen, (x0 + x1) / 2 - 15, (y0 + y1) / 2,
                    L"Enlarge console for help (min 80x25)", s_attr_error);
        return;
    }

    screen_put(screen, x0, y0, BOX_TL, s_attr_border);
    for (int x = x0 + 1; x < x1; x++) screen_put(screen, x, y0, BOX_H, s_attr_border);
    screen_put(screen, x1, y0, BOX_TR, s_attr_border);

    wchar_t title_buf[128];
    swprintf_s(title_buf, _countof(title_buf), L" %s ", book->book_title);
    screen_text(screen, x0 + 2, y0, title_buf, s_attr_help_head);

    for (int y = y0 + 1; y < y1; y++) {
        screen_put(screen, x0, y, BOX_V, s_attr_border);
        screen_put(screen, x1, y, BOX_V, s_attr_border);
    }

    screen_put(screen, x0, y1, BOX_BL, s_attr_border);
    for (int x = x0 + 1; x < x1; x++) screen_put(screen, x, y1, BOX_H, s_attr_border);
    screen_put(screen, x1, y1, BOX_BR, s_attr_border);

    int tab_x = ix0 + 1;
    for (int i = 0; i < book->page_count && tab_x < ix1; i++) {
        int active = (i == tui_state.help_tab);
        WORD tab_attr = active ? s_attr_sel : s_attr_normal;
        wchar_t tab_line[128];
        int tlen;
        if (active) {
            tlen = swprintf_s(tab_line, _countof(tab_line), L"\x25B8%s ", book->pages[i].title);
        } else {
            tlen = swprintf_s(tab_line, _countof(tab_line), L" %s  ", book->pages[i].title);
        }
        if (tab_x + tlen >= ix1) break;
        screen_text(screen, tab_x, iy0, tab_line, tab_attr);
        tab_x += tlen;
    }

    for (int x = ix0; x <= ix1; x++) screen_put(screen, x, iy0 + 1, BOX_H, s_attr_border);

    const HelpPage *page = &book->pages[tui_state.help_tab];

    if (page->intro) {
        screen_text(screen, ix0 + 1, iy0 + 2, page->intro, s_attr_normal);
    }

    int term_w = 3;
    for (int i = 0; i < page->entry_count; i++) {
        int w = (int)wcslen(page->entries[i].term);
        if (w > term_w) term_w = w;
    }
    if (term_w > 16) term_w = 16;

    int term_x = ix0 + 1;
    int desc_x = term_x + term_w + 1;
    int desc_w = ix1 - desc_x + 1;

    tui_state.help_more_below = 0;
    int row = iy0 + 4;
    int placed_count = 0;

    for (int i = tui_state.help_scroll; i < page->entry_count; i++) {
        int need = wrapped_rows(page->entries[i].desc, desc_w);
        int gap  = (i > tui_state.help_scroll) ? 1 : 0;

        if (row + gap + need - 1 > iy1 - 2) {
            /* This entry didn't fit, so there is content below the fold. */
            tui_state.help_more_below = 1;
            break;
        }

        row += gap;
        int start = row;
        screen_text(screen, term_x, start, page->entries[i].term, s_attr_help_head);
        draw_wrapped(screen, desc_x, start, desc_w, page->entries[i].desc, s_attr_normal, need);
        row = start + need;
        placed_count++;

        if (i == tui_state.help_scroll && tui_state.help_scroll > 0) {
            screen_put(screen, ix1, start, L'\x25B2', s_attr_border);
        }
    }

    if (tui_state.help_more_below && placed_count > 0) {
        int last_row = row - 1;
        if (last_row >= iy0 + 4 && last_row <= iy1 - 2) {
            screen_put(screen, ix1, last_row, L'\x25BC', s_attr_border);
        }
    }

    for (int x = ix0; x <= ix1; x++) screen_put(screen, x, iy1 - 1, BOX_H, s_attr_border);

    screen_text(screen, ix0 + 1, iy1,
                L"<-/->  Tab page    Up/Dn scroll    1-4 jump    Esc close", s_attr_border);
}

static void render(void)
{
    ULONGLONG now = GetTickCount64();

    if (tui_state.attached) {
        if (now - tui_state.address_table_last_refresh >= ADDR_TABLE_REFRESH_INTERVAL_MS) {
            addr_table_refresh(&tui_state.address_table);
            tui_state.address_table_last_refresh = now;
        }

        if (now - tui_state.address_table_last_lock >= ADDR_TABLE_LOCK_INTERVAL_MS) {
            bool had_error = false;
            size_t error_index = 0;
            addr_table_lock_write(&tui_state.address_table, &had_error, &error_index);
            tui_state.address_table_last_lock = now;

            if (had_error && error_index < tui_state.address_table.count) {
                wchar_t msg[256];
                const AddrEntry *entry = &tui_state.address_table.entries[error_index];
                swprintf_s(msg, _countof(msg),
                           L"Lock write failed on \"%S\" (0x%llX) -- entry unlocked",
                           entry->label, (unsigned long long)entry->address);
                tui_set_status(msg, TRUE);
            }
        }
    }

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
    if (tui_state.help_open) {
        switch (vk) {
        case VK_ESCAPE: tui_state.help_open = 0; break;
        case VK_LEFT:
            tui_state.help_scroll = 0;
            if (tui_state.help_tab > 0) tui_state.help_tab--;
            else tui_state.help_tab = tui_state.help_book ? tui_state.help_book->page_count - 1 : 0;
            break;
        case VK_RIGHT:
        case VK_TAB:
            tui_state.help_scroll = 0;
            if (tui_state.help_book && tui_state.help_tab + 1 < tui_state.help_book->page_count) tui_state.help_tab++;
            else tui_state.help_tab = 0;
            break;
        case VK_UP:    if (tui_state.help_scroll > 0) tui_state.help_scroll--; break;
        case VK_DOWN:
            if (tui_state.help_more_below) tui_state.help_scroll++;
            break;
        default:
            if (ch >= L'1' && ch <= L'9' && tui_state.help_book) {
                int p = ch - L'1';
                if (p < tui_state.help_book->page_count) {
                    tui_state.help_tab = p;
                    tui_state.help_scroll = 0;
                }
            }
            break;
        }
        return;
    }

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
        if (tui_state.panel == PANEL_SCANNER) {
            if (ch == L'?') {
                const HelpBook *book = tui_help_book_for_panel(tui_state.panel);
                if (book) {
                    tui_state.help_book = book;
                    tui_state.help_open = 1;
                    tui_state.help_tab = 0;
                    tui_state.help_scroll = 0;
                }
            } else if (vk == VK_UP && tui_state.scanner_selected_index > 0) {
                tui_state.scanner_selected_index--;
            } else if (vk == VK_DOWN && tui_state.scanner.has_results &&
                       (size_t)tui_state.scanner_selected_index + 1 < tui_state.scanner.results.count) {
                tui_state.scanner_selected_index++;
            } else if (ch == L'a' && tui_state.scanner.has_results &&
                       (size_t)tui_state.scanner_selected_index < tui_state.scanner.results.count) {
                /* add hit label prompt: focus command bar with "label <name>" */
                unsigned long long addr = tui_state.scanner.results.addresses[tui_state.scanner_selected_index];
                wchar_t prompt[32];
                swprintf_s(prompt, _countof(prompt), L"0x%llX", addr);
                tui_set_status(prompt, FALSE);
                /* Signal to command handler that next command is addentry from scan */
                tui_state.cmd_buf[0] = L'\0';
                tui_state.cmd_len = 0;
                swprintf_s(tui_state.cmd_buf, CMD_BUF_MAX, L"addentry %llX %s ",
                           addr, tui_scan_type_name(tui_state.scanner.param.type));
                tui_state.cmd_len = (int)wcslen(tui_state.cmd_buf);
                tui_state.focus = FOCUS_COMMAND;
            }
        }
        if (tui_state.panel == PANEL_ADDRTABLE) {
            size_t count = tui_state.address_table.count;
            if (vk == VK_UP && tui_state.address_table_selected > 0) {
                tui_state.address_table_selected--;
                if (tui_state.address_table_selected < tui_state.address_table_scroll)
                    tui_state.address_table_scroll = tui_state.address_table_selected;
            } else if (vk == VK_DOWN && tui_state.address_table_selected + 1 < (int)count) {
                tui_state.address_table_selected++;
                int vis_rows = (tui_state.height - 3) - CONTENT_START;
                if (tui_state.address_table_selected >= tui_state.address_table_scroll + vis_rows)
                    tui_state.address_table_scroll = tui_state.address_table_selected - vis_rows + 1;
            } else if (ch == L'd' && count > 0) {
                addr_table_remove(&tui_state.address_table, (size_t)tui_state.address_table_selected);
                if (tui_state.address_table_selected >= (int)count - 1 && tui_state.address_table_selected > 0)
                    tui_state.address_table_selected--;
                tui_set_status(L"Entry removed", FALSE);
            } else if (ch == L'u' && count > 0 && tui_state.address_table.entries[tui_state.address_table_selected].locked) {
                addr_table_unlock(&tui_state.address_table, (size_t)tui_state.address_table_selected);
                tui_set_status(L"Unlocked", FALSE);
            } else if (ch == L'l' && count > 0 && !tui_state.address_table.entries[tui_state.address_table_selected].locked) {
                tui_state.cmd_buf[0] = L'\0';
                tui_state.cmd_len = 0;
                swprintf_s(tui_state.cmd_buf, CMD_BUF_MAX, L"lockentry %d ",
                           tui_state.address_table_selected);
                tui_state.cmd_len = (int)wcslen(tui_state.cmd_buf);
                tui_state.focus = FOCUS_COMMAND;
            } else if (ch == L'e' && count > 0) {
                tui_state.cmd_buf[0] = L'\0';
                tui_state.cmd_len = 0;
                swprintf_s(tui_state.cmd_buf, CMD_BUF_MAX, L"entrylabel %d ",
                           tui_state.address_table_selected);
                tui_state.cmd_len = (int)wcslen(tui_state.cmd_buf);
                tui_state.focus = FOCUS_COMMAND;
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