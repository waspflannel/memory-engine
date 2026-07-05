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

#define CMD_BUF_MAX    256
#define STATUS_MSG_MAX 512

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

    wchar_t cmd_buf[CMD_BUF_MAX];
    int     cmd_len;

    wchar_t   status_msg[STATUS_MSG_MAX];
    int       status_error;
    ULONGLONG status_ticks;

    int running;
} g;

/* ---- screen composition (what to draw; uses render.h for how) ---- */

static void draw_borders(Screen *s)
{
    WORD a = g_attr_border;

    screen_put(s, 0,           0,             BOX_TL, a);
    screen_put(s, g.w - 1,     0,             BOX_TR, a);
    screen_put(s, 0,           g.h - 1,       BOX_BL, a);
    screen_put(s, g.w - 1,     g.h - 1,       BOX_BR, a);

    screen_fill_row(s, 0,       BOX_H, a, 1, g.w - 2);
    screen_fill_row(s, g.h - 1, BOX_H, a, 1, g.w - 2);

    for (int y = 1; y < g.h - 1; y++) {
        screen_put(s, 0,       y, BOX_V, a);
        screen_put(s, g.w - 1, y, BOX_V, a);
    }
}

static void draw_sep_row(Screen *s, int y, int split)
{
    WORD a = g_attr_border;
    int sb_end = 1 + SIDEBAR_WIDTH;

    screen_put(s, 0,       y, BOX_TLEFT,  a);
    screen_put(s, g.w - 1, y, BOX_TRIGHT, a);

    if (split) {
        screen_fill_row(s, y, BOX_H, a, 1, sb_end - 1);
        screen_put(s, sb_end, y, BOX_TTOP, a);
        screen_fill_row(s, y, BOX_H, a, sb_end + 1, g.w - 2);
    } else {
        screen_fill_row(s, y, BOX_H, a, 1, g.w - 2);
    }
}

static void draw_header(Screen *s)
{
    screen_text(s, 2, HEADER_ROW, L"MemForge v0.1", g_attr_header);

    wchar_t status[128];
    if (g.attached) {
        swprintf_s(status, 128, L"[Process: %s PID:%u]", g.target.name, g.target.pid);
    } else {
        swprintf_s(status, 128, L"[No process attached]");
    }
    screen_text_right(s, g.w - 2, HEADER_ROW, status, g_attr_header);

    screen_put(s, 0,       HEADER_ROW, BOX_V, g_attr_border);
    screen_put(s, g.w - 1, HEADER_ROW, BOX_V, g_attr_border);
}

static void draw_sidebar(Screen *s)
{
    int sb_end = 1 + SIDEBAR_WIDTH;

    for (int i = 0; i < PANEL_COUNT; i++) {
        int row = CONTENT_START + i;
        if (row >= g.h - 2) break;

        WORD attr = (i == g.sidebar_idx && g.focus == FOCUS_SIDEBAR)
                      ? g_attr_sel : g_attr_normal;

        for (int x = 1; x < sb_end; x++) {
            screen_put(s, x, row, L' ', attr);
        }
        screen_text(s, 2, row, g_sidebar_labels[i], attr);
    }
}

static void draw_process_list(Screen *s)
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
        screen_text(s, main_x, row, line, attr);
        int used = (int)wcslen(line);
        for (int x = main_x + used; x < g.w - 1; x++) {
            screen_put(s, x, row, L' ', attr);
        }
    }
}

static void draw_main_panel(Screen *s)
{
    int sb_end = 1 + SIDEBAR_WIDTH;
    int main_x = sb_end + 1;
    WORD a = g_attr_border;

    for (int y = CONTENT_START; y < g.h - 2; y++) {
        screen_put(s, sb_end, y, BOX_V, a);
    }

    if (g.panel == PANEL_PROCESSES) {
        if (g.proc_count > 0) {
            draw_process_list(s);
        } else {
            screen_text(s, main_x, CONTENT_START, L"Loading process list...", g_attr_normal);
        }
    } else {
        screen_text(s, main_x, CONTENT_START, L"Not yet implemented", g_attr_normal);
    }
}

static void draw_command(Screen *s)
{
    int cmd_row = g.h - 2;

    wchar_t display[STATUS_MSG_MAX];
    if (g.status_msg[0] && (GetTickCount64() - g.status_ticks) < MAX_STATUS_TICKS) {
        swprintf_s(display, STATUS_MSG_MAX, L" %s", g.status_msg);
        WORD attr = g.status_error ? g_attr_error : g_attr_normal;
        screen_text(s, 1, cmd_row, display, attr);
    } else {
        swprintf_s(display, STATUS_MSG_MAX, L" > %s", g.cmd_buf);
        WORD attr = (g.focus == FOCUS_COMMAND) ? g_attr_sel : g_attr_normal;
        screen_text(s, 1, cmd_row, display, attr);
        if (g.focus == FOCUS_COMMAND) {
            int cursor_x = 4 + g.cmd_len;
            screen_put(s, cursor_x, cmd_row, L' ', g_attr_sel | COMMON_LVB_UNDERSCORE);
        }
    }
}

static void render(void)
{
    Screen s;
    if (screen_alloc(&s, g.w, g.h) != 0) return;

    screen_clear(&s, g_attr_normal);
    draw_borders(&s);
    draw_sep_row(&s, SEP1_ROW, TRUE);
    draw_sep_row(&s, g.h - 3, FALSE);
    draw_header(&s);
    draw_sidebar(&s);
    draw_main_panel(&s);
    draw_command(&s);

    screen_present(&s, g.hOut);
    screen_free(&s);
}

/* ---- app state + actions ---- */

static void set_status(const wchar_t *msg, int is_error)
{
    wcsncpy_s(g.status_msg, STATUS_MSG_MAX, msg, _TRUNCATE);
    g.status_error = is_error;
    g.status_ticks = GetTickCount64();
}

static void refresh_process_list(void)
{
    if (g.procs) {
        process_free_list(g.procs);
        g.procs = NULL;
    }
    g.proc_count = 0;
    g.proc_sel   = 0;
    g.proc_scroll = 0;

    PlatformError err = process_list(&g.procs, &g.proc_count);
    if (err != PLATFORM_OK) {
        set_status(L"Failed to list processes", TRUE);
    }
}

static int do_attach(DWORD pid)
{
    if (g.attached) {
        process_detach(&g.target);
        g.attached = FALSE;
    }

    process_enable_privilege();

    PlatformError err = process_attach(pid, &g.target);
    if (err != PLATFORM_OK) {
        wchar_t msg[512];
        swprintf_s(msg, 512, L"Failed to attach to PID %u: %S", pid, process_error_string(err));
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

    unsigned long long address = 0;
    int size = 0;
    if (swscanf_s(args, L"%llx %d", &address, &size) != 2 || size <= 0 || size > 512) {
        set_status(L"usage: read <hex_address> <size_in_bytes>", TRUE);
        return;
    }

    unsigned char buf[512];
    PlatformError err = memory_read(&g.target, address, buf, (size_t)size);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"read failed: %S", process_error_string(err));
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

    PlatformError err = memory_write(&g.target, address, buf, (size_t)byte_count);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"write failed: %S", process_error_string(err));
        set_status(msg, TRUE);
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, 256, L"Wrote %d byte(s) to 0x%llX", byte_count, address);
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

    if (wcsncmp(g.cmd_buf, L"attach ", CMD_ATTACH_PREFIX) == 0) {
        DWORD pid = (DWORD)_wtol(g.cmd_buf + CMD_ATTACH_PREFIX);
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
            process_detach(&g.target);
            g.attached = FALSE;
            set_status(L"Detached", FALSE);
        } else {
            set_status(L"No process attached", TRUE);
        }
        g.cmd_len = 0;
        return;
    }

    if (wcsncmp(g.cmd_buf, L"read ", CMD_READ_PREFIX) == 0) {
        cmd_read(g.cmd_buf + CMD_READ_PREFIX);
        g.cmd_len = 0;
        return;
    }

    if (wcsncmp(g.cmd_buf, L"write ", CMD_WRITE_PREFIX) == 0) {
        cmd_write(g.cmd_buf + CMD_WRITE_PREFIX);
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
        } else if (ch >= L' ' && g.cmd_len < CMD_BUF_MAX - 1) {
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
        process_detach(&g.target);
        g.attached = FALSE;
    }

    if (g.procs) {
        process_free_list(g.procs);
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
