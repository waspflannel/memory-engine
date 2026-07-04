#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#include "core/process/process.h"
#include "core/memory/memory.h"

#define SIDEBAR_WIDTH   12
#define HEADER_ROW      1
#define SEP1_ROW        2
#define CONTENT_START   3
#define MAX_STATUS_TICKS 3000

enum { FOCUS_SIDEBAR, FOCUS_MAIN, FOCUS_COMMAND };
enum { PANEL_PROCESSES, PANEL_SCANNER, PANEL_ADDRTABLE, PANEL_HEXVIEW,
       PANEL_DISASM, PANEL_DEBUGGER, PANEL_SCRIPTS, PANEL_PROFILES,
       PANEL_COUNT };

static const wchar_t *g_sidebar_labels[PANEL_COUNT] = {
    L"Processes",
    L"Scanner",
    L"AddrTable",
    L"Hex View",
    L"Disasm",
    L"Debugger",
    L"Scripts",
    L"Profiles",
};

static WORD g_attr_normal = 0;
static WORD g_attr_sel    = 0;
static WORD g_attr_header = 0;
static WORD g_attr_border = 0;
static WORD g_attr_error  = 0;

static struct {
    HANDLE hOut;
    HANDLE hIn;
    int    w;
    int    h;

    int focus;
    int panel;
    int sidebar_idx;

    ProcessEntry *procs;
    unsigned int   proc_count;
    int            proc_sel;
    int            proc_scroll;

    Target  target;
    int     attached;

    wchar_t cmd_buf[256];
    int     cmd_len;

    wchar_t status_msg[512];
    int     status_error;
    DWORD   status_ticks;

    int running;
} g;

static void set_cell(CHAR_INFO *buf, int x, int y, WCHAR ch, WORD attr)
{
    if (x < 0 || x >= g.w || y < 0 || y >= g.h) return;
    buf[y * g.w + x].Char.UnicodeChar = ch;
    buf[y * g.w + x].Attributes = attr;
}

static void fill_row(CHAR_INFO *buf, int y, WCHAR ch, WORD attr, int x0, int x1)
{
    for (int x = x0; x <= x1; x++) {
        set_cell(buf, x, y, ch, attr);
    }
}

static void draw_text(CHAR_INFO *buf, int x, int y, const wchar_t *text, WORD attr)
{
    while (*text && x < g.w) {
        set_cell(buf, x++, y, *text++, attr);
    }
}

static void draw_text_right(CHAR_INFO *buf, int right_x, int y, const wchar_t *text, WORD attr)
{
    size_t len = wcslen(text);
    int x = right_x - (int)len + 1;
    if (x < 0) x = 0;
    draw_text(buf, x, y, text, attr);
}

static void clear_area(CHAR_INFO *buf)
{
    for (int i = 0; i < g.w * g.h; i++) {
        buf[i].Char.UnicodeChar = L' ';
        buf[i].Attributes = g_attr_normal;
    }
}

static void draw_borders(CHAR_INFO *buf)
{
    WORD a = g_attr_border;

    set_cell(buf, 0,           0,             L'\x250C', a);
    set_cell(buf, g.w - 1,     0,             L'\x2510', a);
    set_cell(buf, 0,           g.h - 1,       L'\x2514', a);
    set_cell(buf, g.w - 1,     g.h - 1,       L'\x2518', a);

    fill_row(buf, 0,           L'\x2500', a, 1, g.w - 2);
    fill_row(buf, g.h - 1,     L'\x2500', a, 1, g.w - 2);

    for (int y = 1; y < g.h - 1; y++) {
        set_cell(buf, 0,       y, L'\x2502', a);
        set_cell(buf, g.w - 1, y, L'\x2502', a);
    }
}

static void draw_sep_row(CHAR_INFO *buf, int y, int split)
{
    WORD a = g_attr_border;
    int sb_end = 1 + SIDEBAR_WIDTH;

    set_cell(buf, 0,       y, L'\x251C', a);
    set_cell(buf, g.w - 1, y, L'\x2524', a);

    if (split) {
        fill_row(buf, y, L'\x2500', a, 1, sb_end - 1);
        set_cell(buf, sb_end, y, L'\x252C', a);
        fill_row(buf, y, L'\x2500', a, sb_end + 1, g.w - 2);
    } else {
        fill_row(buf, y, L'\x2500', a, 1, g.w - 2);
    }
}

static void draw_header(CHAR_INFO *buf)
{
    draw_text(buf, 2, HEADER_ROW, L"MemForge v0.1", g_attr_header);

    wchar_t status[128];
    if (g.attached) {
        swprintf_s(status, 128, L"[Process: %s PID:%u]", g.target.name, g.target.pid);
    } else {
        swprintf_s(status, 128, L"[No process attached]");
    }
    draw_text_right(buf, g.w - 2, HEADER_ROW, status, g_attr_header);

    set_cell(buf, 0,             HEADER_ROW, L'\x2502', g_attr_border);
    set_cell(buf, g.w - 1,       HEADER_ROW, L'\x2502', g_attr_border);
}

static void draw_sidebar(CHAR_INFO *buf)
{
    int sb_end = 1 + SIDEBAR_WIDTH;

    for (int i = 0; i < PANEL_COUNT; i++) {
        int row = CONTENT_START + i;
        if (row >= g.h - 2) break;

        WORD attr = (i == g.sidebar_idx && g.focus == FOCUS_SIDEBAR)
                      ? g_attr_sel : g_attr_normal;

        for (int x = 1; x < sb_end; x++) {
            set_cell(buf, x, row, L' ', attr);
        }
        draw_text(buf, 2, row, g_sidebar_labels[i], attr);
    }
}

static void draw_process_list(CHAR_INFO *buf)
{
    int main_x = 1 + SIDEBAR_WIDTH + 1;
    int main_w = g.w - main_x - 1;
    if (main_w < 10) return;

    int vis_rows = (g.h - 2) - CONTENT_START;
    if (vis_rows <= 0) return;

    int max_scroll = (int)g.proc_count - vis_rows;
    if (max_scroll < 0) max_scroll = 0;
    if (g.proc_scroll > max_scroll) g.proc_scroll = max_scroll;
    if (g.proc_scroll < 0) g.proc_scroll = 0;

    wchar_t line[256];
    for (int i = 0; i < vis_rows; i++) {
        int pi = g.proc_scroll + i;
        int row = CONTENT_START + i;
        if ((unsigned int)pi >= g.proc_count) break;

        ProcessEntry *pe = &g.procs[pi];
        swprintf_s(line, 256, L"%5u  %s", pe->pid, pe->name);
        WORD attr = (pi == g.proc_sel && g.focus == FOCUS_MAIN)
                      ? g_attr_sel : g_attr_normal;
        draw_text(buf, main_x, row, line, attr);
        int used = (int)wcslen(line);
        for (int x = main_x + used; x < g.w - 1; x++) {
            set_cell(buf, x, row, L' ', attr);
        }
    }
}

static void draw_main_panel(CHAR_INFO *buf)
{
    int sb_end = 1 + SIDEBAR_WIDTH;
    int main_x = sb_end + 1;
    WORD a = g_attr_border;

    for (int y = CONTENT_START; y < g.h - 2; y++) {
        set_cell(buf, sb_end, y, L'\x2502', a);
    }

    if (g.panel == PANEL_PROCESSES) {
        if (g.proc_count > 0) {
            draw_process_list(buf);
        } else {
            draw_text(buf, main_x, CONTENT_START, L"Loading process list...", g_attr_normal);
        }
    } else {
        const wchar_t *msg = L"Not yet implemented";
        draw_text(buf, main_x, CONTENT_START, msg, g_attr_normal);
    }
}

static void draw_command(CHAR_INFO *buf)
{
    int cmd_row = g.h - 2;

    wchar_t display[512];
    if (g.status_msg[0] && (GetTickCount() - g.status_ticks) < MAX_STATUS_TICKS) {
        swprintf_s(display, 512, L" %s", g.status_msg);
        WORD attr = g.status_error ? g_attr_error : g_attr_normal;
        draw_text(buf, 1, cmd_row, display, attr);
    } else {
        swprintf_s(display, 512, L" > %s", g.cmd_buf);
        WORD attr = (g.focus == FOCUS_COMMAND) ? g_attr_sel : g_attr_normal;
        draw_text(buf, 1, cmd_row, display, attr);
        if (g.focus == FOCUS_COMMAND) {
            int cursor_x = 4 + g.cmd_len;
            set_cell(buf, cursor_x, cmd_row, L' ', g_attr_sel | COMMON_LVB_UNDERSCORE);
        }
    }
}

static void render(void)
{
    CHAR_INFO *buf = (CHAR_INFO *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        g.w * g.h * sizeof(CHAR_INFO));
    if (!buf) return;

    clear_area(buf);
    draw_borders(buf);
    draw_sep_row(buf, SEP1_ROW, TRUE);
    draw_sep_row(buf, g.h - 3, FALSE);
    draw_header(buf);
    draw_sidebar(buf);
    draw_main_panel(buf);
    draw_command(buf);

    SMALL_RECT region = { 0, 0, (SHORT)(g.w - 1), (SHORT)(g.h - 1) };
    COORD bufSize = { (SHORT)g.w, (SHORT)g.h };
    COORD bufCoord = { 0, 0 };
    WriteConsoleOutputW(g.hOut, buf, bufSize, bufCoord, &region);

    HeapFree(GetProcessHeap(), 0, buf);
}

static void set_status(const wchar_t *msg, int is_error)
{
    wcsncpy_s(g.status_msg, 512, msg, _TRUNCATE);
    g.status_error = is_error;
    g.status_ticks = GetTickCount();
}

static void refresh_process_list(void)
{
    if (g.procs) {
        proc_free_list(g.procs);
        g.procs = NULL;
    }
    g.proc_count = 0;
    g.proc_sel   = 0;
    g.proc_scroll = 0;

    PlatError err = proc_enumerate(&g.procs, &g.proc_count);
    if (err != PLAT_OK) {
        set_status(L"Failed to enumerate processes", TRUE);
    }
}

static int do_attach(DWORD pid)
{
    if (g.attached) {
        proc_detach(&g.target);
        g.attached = FALSE;
    }

    proc_enable_privilege();

    PlatError err = proc_attach(pid, &g.target);
    if (err != PLAT_OK) {
        wchar_t msg[512];
        swprintf_s(msg, 512, L"Failed to attach to PID %u: %S", pid, proc_error_string(err));
        set_status(msg, TRUE);
        return 0;
    }

    g.attached = TRUE;
    wchar_t msg[256];
    swprintf_s(msg, 256, L"Attached to %s (PID %u)", g.target.name, pid);
    set_status(msg, FALSE);
    return 1;
}

static void attach_to_selected(void)
{
    if (!g.procs || g.proc_count == 0) return;
    if ((unsigned int)g.proc_sel >= g.proc_count) return;

    do_attach(g.procs[g.proc_sel].pid);
}

static void cmd_read(const wchar_t *args)
{
    if (!g.attached) {
        set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long addr = 0;
    int size = 0;
    if (swscanf_s(args, L"%llx %d", &addr, &size) != 2 || size <= 0 || size > 512) {
        set_status(L"usage: read <hex_address> <size_in_bytes>", TRUE);
        return;
    }

    unsigned char buf[512];
    PlatError err = mem_read(&g.target, addr, buf, (size_t)size);
    if (err != PLAT_OK) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"read failed: %S", proc_error_string(err));
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
    if (!g.attached) {
        set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long addr = 0;
    wchar_t hex[256] = {0};
    if (swscanf_s(args, L"%llx %s", &addr, hex, (unsigned int)(sizeof(hex) / sizeof(wchar_t))) != 2) {
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

    PlatError err = mem_write(&g.target, addr, buf, (size_t)byte_count);
    if (err != PLAT_OK) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"write failed: %S", proc_error_string(err));
        set_status(msg, TRUE);
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, 256, L"Wrote %d byte(s) to 0x%llX", byte_count, addr);
    set_status(msg, FALSE);
}

static void exec_command(void)
{
    if (g.cmd_len == 0) return;

    if (wcscmp(g.cmd_buf, L"quit") == 0 || wcscmp(g.cmd_buf, L"exit") == 0) {
        g.running = FALSE;
        g.cmd_len = 0;
        return;
    }

    if (wcsncmp(g.cmd_buf, L"attach ", 7) == 0) {
        DWORD pid = (DWORD)_wtol(g.cmd_buf + 7);
        if (pid == 0) {
            set_status(L"Invalid PID", TRUE);
        } else {
            do_attach(pid);
        }
        g.cmd_len = 0;
        return;
    }

    if (wcscmp(g.cmd_buf, L"detach") == 0) {
        if (g.attached) {
            proc_detach(&g.target);
            g.attached = FALSE;
            set_status(L"Detached", FALSE);
        } else {
            set_status(L"No process attached", TRUE);
        }
        g.cmd_len = 0;
        return;
    }

    if (wcsncmp(g.cmd_buf, L"read ", 5) == 0) {
        cmd_read(g.cmd_buf + 5);
        g.cmd_len = 0;
        return;
    }

    if (wcsncmp(g.cmd_buf, L"write ", 6) == 0) {
        cmd_write(g.cmd_buf + 6);
        g.cmd_len = 0;
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, 256, L"Unknown command: %s", g.cmd_buf);
    set_status(msg, TRUE);
    g.cmd_len = 0;
}

static void handle_key(WORD vk, WCHAR ch)
{
    switch (g.focus) {
    case FOCUS_SIDEBAR:
        if (vk == VK_UP && g.sidebar_idx > 0) {
            g.sidebar_idx--;
        } else if (vk == VK_DOWN && g.sidebar_idx < PANEL_COUNT - 1) {
            g.sidebar_idx++;
        } else if (vk == VK_RETURN) {
            g.panel = g.sidebar_idx;
            g.focus = FOCUS_MAIN;
        } else if (ch == L'q' || ch == L'Q') {
            g.running = FALSE;
        }
        break;

    case FOCUS_MAIN:
        if (g.panel == PANEL_PROCESSES) {
            if (vk == VK_UP && g.proc_sel > 0) {
                g.proc_sel--;
                if (g.proc_sel < g.proc_scroll) g.proc_scroll = g.proc_sel;
            } else if (vk == VK_DOWN && (unsigned int)g.proc_sel + 1 < g.proc_count) {
                g.proc_sel++;
                int vis = (g.h - 2) - CONTENT_START;
                if (g.proc_sel >= g.proc_scroll + vis) g.proc_scroll = g.proc_sel - vis + 1;
            } else if (vk == VK_RETURN) {
                attach_to_selected();
            } else if (vk == VK_F5) {
                refresh_process_list();
                set_status(L"Process list refreshed", FALSE);
            }
        }
        if (vk == VK_ESCAPE) {
            g.focus = FOCUS_SIDEBAR;
        }
        break;

    case FOCUS_COMMAND:
        if (vk == VK_RETURN) {
            exec_command();
        } else if (vk == VK_BACK) {
            if (g.cmd_len > 0) g.cmd_buf[--g.cmd_len] = L'\0';
        } else if (vk == VK_ESCAPE) {
            g.cmd_len = 0;
            g.focus = FOCUS_SIDEBAR;
        } else if (ch >= L' ' && g.cmd_len < 255) {
            g.cmd_buf[g.cmd_len++] = ch;
            g.cmd_buf[g.cmd_len] = L'\0';
        }
        break;
    }

    if (vk == VK_TAB) {
        g.focus = (g.focus + 1) % 3;
    }
}

static void read_input(void)
{
    INPUT_RECORD records[16];
    DWORD count = 0;
    if (!ReadConsoleInputW(g.hIn, records, 16, &count)) return;

    for (DWORD i = 0; i < count; i++) {
        if (records[i].EventType != KEY_EVENT) continue;
        if (!records[i].Event.KeyEvent.bKeyDown) continue;
        handle_key(records[i].Event.KeyEvent.wVirtualKeyCode,
                   records[i].Event.KeyEvent.uChar.UnicodeChar);
    }
}

int tui_init(void)
{
    g.hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    g.hIn  = GetStdHandle(STD_INPUT_HANDLE);

    if (g.hOut == INVALID_HANDLE_VALUE || g.hIn == INVALID_HANDLE_VALUE) {
        return -1;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi = {0};
    if (!GetConsoleScreenBufferInfo(g.hOut, &csbi)) return -1;
    g.w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    g.h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    if (g.w < 80) g.w = 80;
    if (g.h < 25) g.h = 25;

    CONSOLE_CURSOR_INFO ci = {0};
    GetConsoleCursorInfo(g.hOut, &ci);
    ci.bVisible = FALSE;
    SetConsoleCursorInfo(g.hOut, &ci);

    SetConsoleTitleW(L"MemForge");

    DWORD mode;
    GetConsoleMode(g.hIn, &mode);
    mode &= ~ENABLE_PROCESSED_INPUT;
    mode &= ~ENABLE_LINE_INPUT;
    mode &= ~ENABLE_ECHO_INPUT;
    mode |= ENABLE_WINDOW_INPUT;
    SetConsoleMode(g.hIn, mode);

    g_attr_normal = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    g_attr_sel    = BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED |
                    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    g_attr_header = BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN |
                    FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    g_attr_border = FOREGROUND_INTENSITY;
    g_attr_error  = FOREGROUND_RED | FOREGROUND_INTENSITY;

    g.panel        = PANEL_PROCESSES;
    g.sidebar_idx  = 0;
    g.focus        = FOCUS_SIDEBAR;
    g.running      = TRUE;

    memset(&g.target, 0, sizeof(g.target));
    g.attached = FALSE;

    refresh_process_list();

    return 0;
}

void tui_shutdown(void)
{
    CONSOLE_CURSOR_INFO ci = {0};
    GetConsoleCursorInfo(g.hOut, &ci);
    ci.bVisible = TRUE;
    SetConsoleCursorInfo(g.hOut, &ci);

    DWORD mode;
    GetConsoleMode(g.hIn, &mode);
    mode |= ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
    SetConsoleMode(g.hIn, mode);

    if (g.attached) {
        proc_detach(&g.target);
        g.attached = FALSE;
    }

    if (g.procs) {
        proc_free_list(g.procs);
        g.procs = NULL;
    }

    DWORD written;
    COORD zero = {0, 0};
    FillConsoleOutputCharacterW(g.hOut, L' ', (DWORD)(g.w * g.h), zero, &written);
    SetConsoleCursorPosition(g.hOut, zero);
}

void tui_run(void)
{
    while (g.running) {
        render();
        read_input();
    }
}
