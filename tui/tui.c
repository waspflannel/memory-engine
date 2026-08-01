#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "tui/render.h"
#include "tui_internal.h"

#define SIDEBAR_WIDTH   12
#define HEADER_ROW      1
#define SEP1_ROW        2
#define CONTENT_START   3

#define INPUT_RECORD_BATCH 16
#define SCANNER_LIST_ROWS 20
#define MIN_LAYOUT_WIDTH 40
#define MIN_LAYOUT_HEIGHT 10

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
static void draw_hexview_panel(Screen *screen);
static void draw_disasm_panel(Screen *screen);
static void draw_main_panel(Screen *screen);
static void draw_command(Screen *screen);
static void draw_help(Screen *screen);
static int  draw_wrapped(Screen *screen, int x, int y, int max_w, const wchar_t *text, WORD attr, int max_rows);
static int  render(void);
static void prefill_command(const wchar_t *format, ...);
static void handle_key(WORD vk, WCHAR ch);
static void read_input(DWORD timeout);
static void tick_address_table(void);
static void tick_hexview(void);
static void tick_disasm(void);
static int  update_console_size(void);
static void hexview_layout(unsigned short *bytes_per_row, size_t *byte_count);
static void refresh_hexview_window(void);
static void refresh_disasm_window(void);

/* ---- Public API (order matches tui.h) ---- */

int tui_init(void)
{
    tui_state.hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    tui_state.hIn  = GetStdHandle(STD_INPUT_HANDLE);

    if (!tui_state.hOut || !tui_state.hIn ||
        tui_state.hOut == INVALID_HANDLE_VALUE || tui_state.hIn == INVALID_HANDLE_VALUE) {
        return -1;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi = {0};
    if (!GetConsoleScreenBufferInfo(tui_state.hOut, &csbi)) return -1;
    tui_state.width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    tui_state.height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;

    CONSOLE_CURSOR_INFO ci = {0};
    if (!GetConsoleCursorInfo(tui_state.hOut, &ci)) return -1;
    ci.bVisible = FALSE;
    if (!SetConsoleCursorInfo(tui_state.hOut, &ci)) return -1;

    if (!SetConsoleTitleW(L"MemForge")) return -1;

    DWORD mode = 0;
    if (!GetConsoleMode(tui_state.hIn, &mode)) return -1;
    mode &= ~ENABLE_PROCESSED_INPUT;
    mode &= ~ENABLE_LINE_INPUT;
    mode &= ~ENABLE_ECHO_INPUT;
    mode |= ENABLE_WINDOW_INPUT;
    if (!SetConsoleMode(tui_state.hIn, mode)) return -1;

    tui_state.running = TRUE;

    if (!addr_table_init(&tui_state.address_table, NULL)) return -1;
    tui_state.hexview_high_nibble = -1;

    tui_refresh_process_list();

    return 0;
}

void tui_run(void)
{
    while (tui_state.running) {
        tick_address_table();
        tick_hexview();
        tick_disasm();
        if (render() != 0) {
            tui_state.running = FALSE;
            break;
        }
        ULONGLONG now = GetTickCount64();
        read_input(tui_next_wait_timeout(now));
    }
}

void tui_shutdown(void)
{
    CONSOLE_CURSOR_INFO ci = {0};
    GetConsoleCursorInfo(tui_state.hOut, &ci);
    ci.bVisible = TRUE;
    SetConsoleCursorInfo(tui_state.hOut, &ci);

    DWORD mode = 0;
    if (GetConsoleMode(tui_state.hIn, &mode)) {
        mode |= ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
        SetConsoleMode(tui_state.hIn, mode);
    }

    tui_detach_target();

    addr_table_destroy(&tui_state.address_table);

    if (tui_state.processes) {
        process_free_list(tui_state.processes);
        tui_state.processes = NULL;
    }
    if (tui_state.process_view) {
        free(tui_state.process_view);
        tui_state.process_view = NULL;
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

    int max_scroll = (int)tui_state.process_view_count - vis_rows;
    if (max_scroll < 0) max_scroll = 0;
    if (tui_state.process_scroll > max_scroll) tui_state.process_scroll = max_scroll;
    if (tui_state.process_scroll < 0) tui_state.process_scroll = 0;

    wchar_t line[PROCESS_NAME_MAX + 16];
    for (int i = 0; i < vis_rows; i++) {
        int pi = tui_state.process_scroll + i;
        int row = CONTENT_START + i;
        if ((unsigned int)pi >= tui_state.process_view_count) break;

        ProcessEntry *entry = &tui_state.processes[tui_state.process_view[pi]];
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
        if (tui_state.process_count == 0) {
            screen_text(screen, main_x, CONTENT_START, L"Loading process list...", s_attr_normal);
        } else if (tui_state.process_view_count == 0) {
            wchar_t hint[PROCESS_NAME_MAX + 48];
            swprintf_s(hint, _countof(hint),
                       L"No processes match \"%s\"  (Esc clears, F5 refreshes)",
                       tui_state.process_filter);
            screen_text(screen, main_x, CONTENT_START, hint, s_attr_normal);
        } else {
            draw_process_list(screen);
        }
    } else if (tui_state.panel == PANEL_SCANNER) {
        draw_scanner_panel(screen);
    } else if (tui_state.panel == PANEL_ADDRTABLE) {
        draw_address_table_panel(screen);
    } else if (tui_state.panel == PANEL_HEXVIEW) {
        draw_hexview_panel(screen);
    } else if (tui_state.panel == PANEL_DISASM) {
        draw_disasm_panel(screen);
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
    swprintf_s(line, _countof(line), L"Scanner -- type: %s  exact  enc: %s",
               tui_scan_type_name(s->param.type), enc);
    screen_text(screen, main_x, row++, line, s_attr_normal);

    /* Hex byte dump of the current param (works for every type). */
    wchar_t hex[160];
    int pos = swprintf_s(hex, _countof(hex), L"value(hex): ");
    unsigned short shown = s->param.width > 16 ? 16 : s->param.width;
    for (unsigned short i = 0; i < shown && pos + 4 < (int)_countof(hex); i++) {
        pos += swprintf_s(hex + pos, _countof(hex) - pos, L"%02X ", s->param.bytes[i]);
    }
    if (s->param.width > 16) {
        pos += swprintf_s(hex + pos, _countof(hex) - pos, L"...");
    }
    if (s->results.skipped_regions > 0) {
        swprintf_s(line, _countof(line), L"%s  results: %llu  ignored regions: %llu", hex,
                   (unsigned long long)s->results.count,
                   (unsigned long long)s->results.skipped_regions);
        screen_text(screen, main_x, row++, line, s_attr_normal);
    } else if (s->results.unreadable_candidates > 0) {
        swprintf_s(line, _countof(line), L"%s  results: %llu  unreadable removed: %llu", hex,
                   (unsigned long long)s->results.count,
                   (unsigned long long)s->results.unreadable_candidates);
        screen_text(screen, main_x, row++, line, s_attr_normal);
    } else {
        swprintf_s(line, _countof(line), L"%s  results: %llu", hex,
                   (unsigned long long)s->results.count);
        screen_text(screen, main_x, row++, line, s_attr_normal);
    }

    row++;  /* blank separator */

    if (!s->has_results) {
        screen_text(screen, main_x, row, L"Run `scan <value>` to find (use `type <name>` to pick type)", s_attr_normal);
    } else if (s->results.count == 0 && s->results.skipped_regions > 0) {
        screen_text(screen, main_x, row, L"No hits; volatile regions were ignored", s_attr_normal);
    } else if (s->results.count == 0 && s->results.unreadable_candidates > 0) {
        screen_text(screen, main_x, row, L"No survivors; unreadable candidates were removed", s_attr_normal);
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
        unsigned short value_width = scanner_type_width(entry->type);
        int is_sel = (ei == tui_state.address_table_selected && tui_state.focus == FOCUS_MAIN);
        WORD attr = is_sel ? s_attr_sel : s_attr_normal;

        const wchar_t *lock_char = entry->locked ? L"L" : L" ";
        const wchar_t *value_str = L"?";

        wchar_t val_buf[64];
        if (!entry->value_valid) {
            if (!tui_state.attached) {
                value_str = L"no process";
            } else {
                value_str = L"err";
            }
        } else {
            int pos = 0;
            for (unsigned short k = 0; k < value_width && pos < 45; k++) {
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
                    L"d del  l lock  u unlock  e label  r read  w write  v hex  ? help",
                    s_attr_border);
    }
}

static void draw_hexview_panel(Screen *screen)
{
    int main_x = 1 + SIDEBAR_WIDTH + 1;
    int main_w = tui_state.width - main_x - 1;
    if (main_w < 10) return;

    if (!tui_state.attached) {
        screen_text(screen, main_x, CONTENT_START,
                    L"Attach to a process first, then use `hex <address>` to jump", s_attr_normal);
        return;
    }

    if (!tui_state.hexview_window_valid) {
        wchar_t line[96];
        swprintf_s(line, _countof(line), L"Hex window unavailable at 0x%016llX",
                   tui_state.hexview_address);
        screen_text(screen, main_x, CONTENT_START, line, s_attr_error);
        return;
    }

    wchar_t header[192];
    swprintf_s(header, _countof(header), L"Hex View  0x%016llX  region: 0x%016llX + 0x%llX  protect: 0x%X",
               tui_state.hexview_address, tui_state.hexview_first_region.base,
               (unsigned long long)tui_state.hexview_first_region.size,
               tui_state.hexview_first_region.protect);
    screen_text(screen, main_x, CONTENT_START, header, s_attr_normal);
    screen_text(screen, main_x, CONTENT_START + 1,
                L"Address             Hex bytes                                      ASCII", s_attr_border);

    int row = CONTENT_START + 2;
    size_t rows = tui_state.hexview_byte_count / tui_state.hexview_bytes_per_row;
    for (size_t line_index = 0; line_index < rows; line_index++) {
        size_t first_byte = line_index * tui_state.hexview_bytes_per_row;
        wchar_t address[24];
        swprintf_s(address, _countof(address), L"0x%016llX", tui_state.hexview_address + first_byte);
        screen_text(screen, main_x, row + (int)line_index, address, s_attr_normal);

        int hex_x = main_x + 19;
        int ascii_x = hex_x + tui_state.hexview_bytes_per_row * 3 + 1;
        screen_put(screen, ascii_x, row + (int)line_index, L'|', s_attr_border);
        for (unsigned short column = 0; column < tui_state.hexview_bytes_per_row; column++) {
            size_t byte_index = first_byte + column;
            int selected = tui_state.focus == FOCUS_MAIN && byte_index == tui_state.hexview_cursor;
            WORD attr = selected ? s_attr_sel :
                (tui_state.hexview_readable[byte_index] ? s_attr_normal : s_attr_error);
            wchar_t cell[4];
            if (selected && tui_state.hexview_high_nibble >= 0) {
                swprintf_s(cell, _countof(cell), L"%X_", tui_state.hexview_high_nibble);
            } else if (tui_state.hexview_readable[byte_index]) {
                swprintf_s(cell, _countof(cell), L"%02X", tui_state.hexview_bytes[byte_index]);
            } else {
                swprintf_s(cell, _countof(cell), L"??");
            }
            screen_text(screen, hex_x + column * 3, row + (int)line_index, cell, attr);

            wchar_t ascii = L'?';
            if (tui_state.hexview_readable[byte_index]) {
                unsigned char byte = tui_state.hexview_bytes[byte_index];
                ascii = byte >= 32 && byte <= 126 ? (wchar_t)byte : L'.';
            }
            screen_put(screen, ascii_x + 1 + column, row + (int)line_index, ascii, attr);
        }
        screen_put(screen, ascii_x + 1 + tui_state.hexview_bytes_per_row,
                   row + (int)line_index, L'|', s_attr_border);
    }

    int help_row = tui_state.height - 4;
    if (help_row > row + (int)rows) {
        screen_text(screen, main_x, help_row,
                    L"Arrows move  PgUp/PgDn page  0-9/A-F edit  g jump  ? help", s_attr_border);
    }
}

static void draw_disasm_panel(Screen *screen)
{
    int main_x = 1 + SIDEBAR_WIDTH + 1;
    int main_w = tui_state.width - main_x - 1;
    if (main_w < 10) return;

    if (!tui_state.attached) {
        screen_text(screen, main_x, CONTENT_START,
                    L"Attach to a process first, then use `disasm <address>` to jump", s_attr_normal);
        return;
    }

    if (!tui_state.disasm_window_valid) {
        wchar_t line[96];
        swprintf_s(line, _countof(line), L"Disassembly unavailable at 0x%016llX",
                   tui_state.disasm_address);
        screen_text(screen, main_x, CONTENT_START, line, s_attr_error);
        return;
    }

    screen_text(screen, main_x, CONTENT_START, L"Disasm  x64  Intel syntax", s_attr_normal);
    int footer_row = tui_state.height - 4;
    int visible_rows = footer_row - (CONTENT_START + 1);
    if (visible_rows < 1) visible_rows = 1;

    if (tui_state.disasm_result.count == 0) {
        screen_text(screen, main_x, CONTENT_START + 1,
                    L"No complete instructions in this readable window", s_attr_error);
    } else {
        if (tui_state.disasm_selected >= tui_state.disasm_result.count) {
            tui_state.disasm_selected = tui_state.disasm_result.count - 1;
        }
        size_t max_scroll = tui_state.disasm_result.count > (size_t)visible_rows
            ? tui_state.disasm_result.count - (size_t)visible_rows : 0;
        if (tui_state.disasm_scroll > max_scroll) tui_state.disasm_scroll = max_scroll;
        if (tui_state.disasm_selected < tui_state.disasm_scroll) {
            tui_state.disasm_scroll = tui_state.disasm_selected;
        } else if (tui_state.disasm_selected >= tui_state.disasm_scroll + (size_t)visible_rows) {
            tui_state.disasm_scroll = tui_state.disasm_selected - (size_t)visible_rows + 1;
        }

        int row = CONTENT_START + 1;
        for (size_t i = tui_state.disasm_scroll;
             i < tui_state.disasm_result.count && row < footer_row; i++, row++) {
            const DisasmInstruction *instruction = &tui_state.disasm_result.instructions[i];
            wchar_t bytes[DISASM_MAX_INSTRUCTION_BYTES * 3 + 1];
            bytes[0] = L'\0';
            int byte_pos = 0;
            for (unsigned char j = 0; j < instruction->length; j++) {
                byte_pos += swprintf_s(bytes + byte_pos, _countof(bytes) - (size_t)byte_pos,
                                       L"%02X ", instruction->bytes[j]);
            }

            wchar_t line[DISASM_OPERANDS_MAX + 128];
            int selected = tui_state.focus == FOCUS_MAIN && i == tui_state.disasm_selected;
            if (instruction->has_relative_target) {
                _snwprintf_s(line, _countof(line), _TRUNCATE,
                             L"%c  0x%016llX  %-45s %-10S %S  -> 0x%016llX",
                             selected ? L'>' : L' ', instruction->address, bytes,
                             instruction->mnemonic, instruction->operands,
                             instruction->relative_target);
            } else {
                _snwprintf_s(line, _countof(line), _TRUNCATE,
                             L"%c  0x%016llX  %-45s %-10S %S",
                             selected ? L'>' : L' ', instruction->address, bytes,
                             instruction->mnemonic, instruction->operands);
            }
            screen_text(screen, main_x, row, line, selected ? s_attr_sel : s_attr_normal);
        }
    }

    if (footer_row > CONTENT_START + 1) {
        screen_text(screen, main_x, footer_row,
                    L"Up/Dn scroll  PgUp/PgDn page  f follow  g jump  ? help", s_attr_border);
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

static int render(void)
{
    Screen screen;
    if (screen_alloc(&screen, tui_state.width, tui_state.height) != 0) {
        tui_set_status(L"Screen allocation failed", TRUE);
        return -1;
    }

    screen_clear(&screen, s_attr_normal);
    if (tui_state.width < MIN_LAYOUT_WIDTH || tui_state.height < MIN_LAYOUT_HEIGHT) {
        screen_text(&screen, 0, 0, L"Resize console to at least 40 x 10", s_attr_error);
        int present_result = screen_present(&screen, tui_state.hOut);
        screen_free(&screen);
        return present_result;
    }
    draw_borders(&screen);
    draw_sep_row(&screen, SEP1_ROW, TRUE);
    draw_sep_row(&screen, tui_state.height - 3, FALSE);
    draw_header(&screen);
    draw_sidebar(&screen);
    draw_main_panel(&screen);
    draw_command(&screen);

    int present_result = screen_present(&screen, tui_state.hOut);
    screen_free(&screen);
    if (present_result != 0) tui_set_status(L"Console output failed", TRUE);
    return present_result;
}

/* ---- Static helpers: input ---- */

static void prefill_command(const wchar_t *format, ...)
{
    va_list args;
    va_start(args, format);
    vswprintf_s(tui_state.cmd_buf, CMD_BUF_MAX, format, args);
    va_end(args);
    tui_state.cmd_len = (int)wcslen(tui_state.cmd_buf);
    tui_state.focus = FOCUS_COMMAND;
}

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
            if (ch == L'?') {
                tui_open_help();
            } else if (ch == L'/') {
                /* Jump to the command bar pre-filled with `search ` so the
                   user can type a substring and Enter to filter the list. */
                prefill_command(L"search ");
            } else if (vk == VK_UP && tui_state.selected_process > 0) {
                tui_state.selected_process--;
                if (tui_state.selected_process < tui_state.process_scroll) tui_state.process_scroll = tui_state.selected_process;
            } else if (vk == VK_DOWN && (unsigned int)tui_state.selected_process + 1 < tui_state.process_view_count) {
                tui_state.selected_process++;
                int vis_rows = (tui_state.height - 3) - CONTENT_START;
                if (tui_state.selected_process >= tui_state.process_scroll + vis_rows) tui_state.process_scroll = tui_state.selected_process - vis_rows + 1;
            } else if (vk == VK_RETURN) {
                tui_attach_to_selected();
            } else if (vk == VK_F5) {
                if (tui_refresh_process_list()) tui_set_status(L"Process list refreshed", FALSE);
            } else if (vk == VK_ESCAPE && tui_state.process_filter[0] != L'\0') {
                /* Esc on a filtered list clears the filter instead of bouncing
                   back to the sidebar -- one keystroke to widen the view. */
                tui_set_process_filter(L"");
                return;
            }
        }
        if (tui_state.panel == PANEL_SCANNER) {
            if (ch == L'?') {
                tui_open_help();
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
                prefill_command(L"addentry %llX %s ", addr,
                                tui_scan_type_name(tui_state.scanner.param.type));
            } else if (ch == L'r' && tui_state.scanner.has_results &&
                       (size_t)tui_state.scanner_selected_index < tui_state.scanner.results.count) {
                unsigned long long addr = tui_state.scanner.results.addresses[tui_state.scanner_selected_index];
                prefill_command(L"read %llX ", addr);
            } else if (ch == L'w' && tui_state.scanner.has_results &&
                       (size_t)tui_state.scanner_selected_index < tui_state.scanner.results.count) {
                unsigned long long addr = tui_state.scanner.results.addresses[tui_state.scanner_selected_index];
                prefill_command(L"write %llX ", addr);
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
                prefill_command(L"lockentry %d ", tui_state.address_table_selected);
            } else if (ch == L'e' && count > 0) {
                prefill_command(L"entrylabel %d ", tui_state.address_table_selected);
            } else if (ch == L'r' && count > 0) {
                /* Read the selected entry's address -- opens the command bar
                   pre-filled with `read <addr> `; type the byte count (1-128)
                   and Enter. Mirrors the `r` shortcut on the Scanner panel so
                   the same muscle memory works on either page. */
                unsigned long long addr = tui_state.address_table.entries[tui_state.address_table_selected].address;
                prefill_command(L"read %llX ", addr);
            } else if (ch == L'w' && count > 0) {
                /* Write to the selected entry's address -- opens the command
                   bar pre-filled with `write <addr> `; type hex byte pairs and
                   Enter. Same contract as the Scanner `w` shortcut. */
                unsigned long long addr = tui_state.address_table.entries[tui_state.address_table_selected].address;
                prefill_command(L"write %llX ", addr);
            } else if (ch == L'v' && count > 0) {
                tui_hexview_jump(tui_state.address_table.entries[tui_state.address_table_selected].address);
            } else if (ch == L'?') {
                tui_open_help();
            }
        }
        if (tui_state.panel == PANEL_HEXVIEW) {
            if (ch == L'?') {
                tui_open_help();
            } else if (ch == L'g' || ch == L'G') {
                prefill_command(L"hex ");
            } else if (vk == VK_LEFT) {
                if (tui_state.hexview_cursor > 0) tui_state.hexview_cursor--;
                else if (tui_state.hexview_address > 0) tui_state.hexview_address--;
                tui_state.hexview_last_refresh = 0;
                tui_state.hexview_high_nibble = -1;
            } else if (vk == VK_RIGHT) {
                if (tui_state.hexview_cursor + 1 < tui_state.hexview_byte_count) tui_state.hexview_cursor++;
                else if (tui_state.hexview_address < ULLONG_MAX) tui_state.hexview_address++;
                tui_state.hexview_last_refresh = 0;
                tui_state.hexview_high_nibble = -1;
            } else if (vk == VK_UP) {
                size_t step = tui_state.hexview_bytes_per_row;
                if (tui_state.hexview_cursor >= step) tui_state.hexview_cursor -= step;
                else if (tui_state.hexview_address >= step) tui_state.hexview_address -= step;
                else tui_state.hexview_address = 0;
                tui_state.hexview_last_refresh = 0;
                tui_state.hexview_high_nibble = -1;
            } else if (vk == VK_DOWN) {
                size_t step = tui_state.hexview_bytes_per_row;
                if (tui_state.hexview_cursor + step < tui_state.hexview_byte_count) {
                    tui_state.hexview_cursor += step;
                } else if (tui_state.hexview_address <= ULLONG_MAX - step) {
                    tui_state.hexview_address += step;
                }
                tui_state.hexview_last_refresh = 0;
                tui_state.hexview_high_nibble = -1;
            } else if (vk == VK_PRIOR) {
                size_t step = tui_state.hexview_byte_count;
                tui_state.hexview_address = tui_state.hexview_address >= step ?
                    tui_state.hexview_address - step : 0;
                tui_state.hexview_cursor = 0;
                tui_state.hexview_last_refresh = 0;
                tui_state.hexview_high_nibble = -1;
            } else if (vk == VK_NEXT) {
                size_t step = tui_state.hexview_byte_count;
                if (tui_state.hexview_address <= ULLONG_MAX - step) {
                    tui_state.hexview_address += step;
                }
                tui_state.hexview_cursor = 0;
                tui_state.hexview_last_refresh = 0;
                tui_state.hexview_high_nibble = -1;
            } else if (tui_hex_digit_value(ch) >= 0) {
                int nibble = tui_hex_digit_value(ch);
                if (tui_state.hexview_cursor >= tui_state.hexview_byte_count ||
                    !tui_state.hexview_readable[tui_state.hexview_cursor]) {
                    tui_set_status(L"Cannot edit an unreadable byte", TRUE);
                } else if (tui_state.hexview_high_nibble < 0) {
                    tui_state.hexview_high_nibble = nibble;
                    tui_set_status(L"Hex high nibble entered; enter the low nibble", FALSE);
                } else {
                    unsigned char byte = (unsigned char)((tui_state.hexview_high_nibble << 4) | nibble);
                    unsigned long long address = tui_state.hexview_address + tui_state.hexview_cursor;
                    PlatformError err = memory_write(&tui_state.target, address, &byte, sizeof(byte));
                    tui_state.hexview_high_nibble = -1;
                    refresh_hexview_window();
                    if (err != PLATFORM_OK) {
                        wchar_t message[256];
                        swprintf_s(message, _countof(message), L"Hex write failed: %S", process_error_string(err));
                        tui_set_status(message, TRUE);
                    } else {
                        wchar_t message[128];
                        swprintf_s(message, _countof(message), L"Wrote %02X to 0x%016llX", byte, address);
                        tui_set_status(message, FALSE);
                    }
                }
            }
        }
        if (tui_state.panel == PANEL_DISASM) {
            size_t count = tui_state.disasm_result.count;
            int footer_row = tui_state.height - 4;
            int visible_rows = footer_row - (CONTENT_START + 1);
            if (visible_rows < 1) visible_rows = 1;

            if (ch == L'?') {
                tui_open_help();
            } else if (ch == L'g' || ch == L'G') {
                prefill_command(L"disasm ");
            } else if (ch == L'f' || ch == L'F') {
                if (count == 0 || tui_state.disasm_selected >= count) {
                    tui_set_status(L"No instruction selected", TRUE);
                } else if (!tui_state.disasm_result.instructions[tui_state.disasm_selected].has_relative_target) {
                    tui_set_status(L"Selected instruction has no direct relative target", TRUE);
                } else {
                    tui_disasm_jump(tui_state.disasm_result.instructions[tui_state.disasm_selected].relative_target);
                }
            } else if (vk == VK_UP && tui_state.disasm_selected > 0) {
                tui_state.disasm_selected--;
                if (tui_state.disasm_selected < tui_state.disasm_scroll)
                    tui_state.disasm_scroll = tui_state.disasm_selected;
            } else if (vk == VK_DOWN && count > 0) {
                if (tui_state.disasm_selected + 1 < count) {
                    tui_state.disasm_selected++;
                    if (tui_state.disasm_selected >= tui_state.disasm_scroll + (size_t)visible_rows)
                        tui_state.disasm_scroll = tui_state.disasm_selected - (size_t)visible_rows + 1;
                } else {
                    const DisasmInstruction *last = &tui_state.disasm_result.instructions[count - 1];
                    if (last->address <= ULLONG_MAX - last->length) {
                        tui_disasm_jump(last->address + last->length);
                    } else {
                        tui_set_status(L"Cannot scroll past the end of address space", TRUE);
                    }
                }
            } else if (vk == VK_PRIOR && count > 0) {
                size_t step = (size_t)visible_rows;
                tui_state.disasm_selected = tui_state.disasm_selected >= step
                    ? tui_state.disasm_selected - step : 0;
                if (tui_state.disasm_selected < tui_state.disasm_scroll)
                    tui_state.disasm_scroll = tui_state.disasm_selected;
            } else if (vk == VK_NEXT && count > 0) {
                size_t step = (size_t)visible_rows;
                size_t selected = tui_state.disasm_selected + step;
                tui_state.disasm_selected = selected < count ? selected : count - 1;
                if (tui_state.disasm_selected >= tui_state.disasm_scroll + (size_t)visible_rows)
                    tui_state.disasm_scroll = tui_state.disasm_selected - (size_t)visible_rows + 1;
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

static void read_input(DWORD timeout)
{
    INPUT_RECORD records[INPUT_RECORD_BATCH];
    DWORD count = 0;
    DWORD wait = WaitForSingleObject(tui_state.hIn, timeout);
    if (wait == WAIT_TIMEOUT) return;
    if (wait != WAIT_OBJECT_0 || !ReadConsoleInputW(tui_state.hIn, records, INPUT_RECORD_BATCH, &count)) {
        tui_set_status(L"Console input failed", TRUE);
        tui_state.running = FALSE;
        return;
    }

    for (DWORD i = 0; i < count; i++) {
        if (records[i].EventType == WINDOW_BUFFER_SIZE_EVENT) {
            if (!update_console_size()) tui_state.running = FALSE;
            continue;
        }
        if (records[i].EventType != KEY_EVENT) continue;
        if (!records[i].Event.KeyEvent.bKeyDown) continue;
        handle_key(records[i].Event.KeyEvent.wVirtualKeyCode,
                   records[i].Event.KeyEvent.uChar.UnicodeChar);
    }
}

static void tick_address_table(void)
{
    if (!tui_state.attached) return;
    ULONGLONG now = GetTickCount64();
    if (now - tui_state.address_table_last_refresh >= ADDR_TABLE_REFRESH_INTERVAL_MS) {
        int alive = 0;
        PlatformError alive_error = process_is_alive(&tui_state.target, &alive);
        if (alive_error != PLATFORM_OK || !alive) {
            tui_detach_target();
            tui_set_status(L"Target process exited -- locks disabled", TRUE);
            return;
        }
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
            swprintf_s(msg, _countof(msg), L"Lock write failed on \"%S\" (0x%llX) -- entry unlocked",
                       entry->label, (unsigned long long)entry->address);
            tui_set_status(msg, TRUE);
        }
    }
}

static void tick_hexview(void)
{
    if (!tui_state.attached || tui_state.panel != PANEL_HEXVIEW) return;

    unsigned short bytes_per_row = 0;
    size_t byte_count = 0;
    hexview_layout(&bytes_per_row, &byte_count);
    if (bytes_per_row != tui_state.hexview_bytes_per_row || byte_count != tui_state.hexview_byte_count) {
        tui_state.hexview_bytes_per_row = bytes_per_row;
        tui_state.hexview_byte_count = byte_count;
        if (tui_state.hexview_cursor >= byte_count) tui_state.hexview_cursor = byte_count - 1;
        tui_state.hexview_last_refresh = 0;
    }

    ULONGLONG now = GetTickCount64();
    if (now - tui_state.hexview_last_refresh < HEXVIEW_REFRESH_INTERVAL_MS &&
        tui_state.hexview_window_valid) return;
    refresh_hexview_window();
    tui_state.hexview_last_refresh = now;
}

static void tick_disasm(void)
{
    if (!tui_state.attached || tui_state.panel != PANEL_DISASM) return;

    ULONGLONG now = GetTickCount64();
    if (now - tui_state.disasm_last_refresh < DISASM_REFRESH_INTERVAL_MS &&
        tui_state.disasm_window_valid) return;
    refresh_disasm_window();
    tui_state.disasm_last_refresh = now;
}

static void hexview_layout(unsigned short *bytes_per_row, size_t *byte_count)
{
    int main_x = 1 + SIDEBAR_WIDTH + 1;
    int main_w = tui_state.width - main_x - 1;
    int columns = (main_w - 23) / 4;
    if (columns < 1) columns = 1;
    if (columns > 16) columns = 16;

    int rows = tui_state.height - CONTENT_START - 6;
    if (rows < 1) rows = 1;
    size_t count = (size_t)columns * (size_t)rows;
    if (count > HEXVIEW_WINDOW_MAX) count = HEXVIEW_WINDOW_MAX;
    *bytes_per_row = (unsigned short)columns;
    *byte_count = count - count % (size_t)columns;
}

static void refresh_hexview_window(void)
{
    memset(tui_state.hexview_readable, 0, sizeof(tui_state.hexview_readable));
    tui_state.hexview_window_valid = FALSE;
    PlatformError err = hexview_read_window(&tui_state.target, tui_state.hexview_address,
                                            tui_state.hexview_bytes, tui_state.hexview_readable,
                                            tui_state.hexview_byte_count,
                                            &tui_state.hexview_first_region);
    if (err != PLATFORM_OK) {
        wchar_t message[256];
        swprintf_s(message, _countof(message), L"Hex view read failed: %S", process_error_string(err));
        tui_set_status(message, TRUE);
        return;
    }
    tui_state.hexview_window_valid = TRUE;
}

static void refresh_disasm_window(void)
{
    tui_state.disasm_window_valid = FALSE;
    tui_state.disasm_result = (DisasmResult){0};

    PlatformError err = disasm_read(&tui_state.target, tui_state.disasm_address,
                                    &tui_state.disasm_result);
    if (err != PLATFORM_OK) {
        wchar_t message[256];
        swprintf_s(message, _countof(message), L"Disasm read failed: %S", process_error_string(err));
        tui_set_status(message, TRUE);
        return;
    }
    tui_state.disasm_window_valid = TRUE;
}

static int update_console_size(void)
{
    CONSOLE_SCREEN_BUFFER_INFO info = {0};
    if (!GetConsoleScreenBufferInfo(tui_state.hOut, &info)) {
        tui_set_status(L"Failed to read console size", TRUE);
        return 0;
    }
    tui_state.width = info.srWindow.Right - info.srWindow.Left + 1;
    tui_state.height = info.srWindow.Bottom - info.srWindow.Top + 1;
    return tui_state.width > 0 && tui_state.height > 0;
}
