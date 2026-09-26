/* Exercise the actual private input, draw, and timer functions without adding
   production test hooks. The separate console test drives the executable. */
#include "tui/tui.c"
#include <stdio.h>
#include "test/test.h"

static void command(const wchar_t *text)
{
    wcscpy_s(tui_state.cmd_buf, CMD_BUF_MAX, text);
    tui_state.cmd_len = (int)wcslen(text);
    handle_key(VK_RETURN, L'\r');
}

static int selection_visible(const Screen *screen)
{
    for (int y = CONTENT_START; y < screen->height - 3; y++) {
        for (int x = SIDEBAR_WIDTH + 2; x < screen->width - 1; x++) {
            if (screen->cells[y * screen->width + x].Attributes == s_attr_sel) return 1;
        }
    }
    return 0;
}

static void test_selection_and_commands(void)
{
    unsigned char memory[128] = {0};
    for (int i = 0; i < 25; i++) {
        wchar_t text[128];
        swprintf_s(text, _countof(text), L"addentry %llX i32 entry%d",
                   (unsigned long long)(UINT_PTR)memory, i);
        command(text);
    }
    tui_state.scanner.has_results = 1;
    tui_state.scanner.results.value_width = 4;
    tui_state.scanner.results.count = 30;
    tui_state.scanner.results.addresses = calloc(30, sizeof(unsigned long long));
    check(tui_state.scanner.results.addresses != NULL, "allocate selected-result fixture");
    if (!tui_state.scanner.results.addresses) return;
    const int sizes[][2] = {{80, 25}, {40, 10}, {40, 12}, {120, 40}};
    for (size_t i = 0; i < _countof(sizes); i++) {
        tui_state.width = sizes[i][0];
        tui_state.height = sizes[i][1];
        Screen screen;
        if (screen_alloc(&screen, tui_state.width, tui_state.height) != 0) {
            check(0, "allocate render fixture");
            continue;
        }
        tui_state.focus = FOCUS_MAIN;
        tui_state.scanner_selected_index = 20;
        screen_clear(&screen, s_attr_normal);
        draw_scanner_panel(&screen);
        draw_command(&screen);
        check(selection_visible(&screen), "scrolled scanner selection remains above the footer");
        screen_clear(&screen, s_attr_normal);
        draw_address_table_panel(&screen);
        draw_command(&screen);
        check(selection_visible(&screen), "new address-table selection follows scrolling and resizing");
        screen_free(&screen);
    }

    tui_state.focus = FOCUS_COMMAND;
    command(L"search");
    check(tui_state.cmd_len == 0 && tui_state.cmd_buf[0] == L'\0', "execution clears visible command text");
    wcscpy_s(tui_state.cmd_buf, CMD_BUF_MAX, L"cancel me");
    tui_state.cmd_len = 9;
    handle_key(VK_ESCAPE, 0);
    check(tui_state.cmd_len == 0 && tui_state.cmd_buf[0] == L'\0', "Escape clears visible command text");

    tui_state.focus = FOCUS_COMMAND;
    tui_state.width = 80;
    tui_state.height = 25;
    wchar_t text[128];
    swprintf_s(text, _countof(text), L"read %llX 128", (unsigned long long)(UINT_PTR)memory);
    command(text);
    check(!tui_state.status_error && tui_state.panel == PANEL_HEXVIEW &&
          tui_state.hexview_address == (UINT_PTR)memory, "long read opens a navigable hex view");
    tick_hexview();
    check(tui_state.hexview_window_valid, "long read has a real readable hex window");
    tui_state.panel = PANEL_PROCESSES;
    swprintf_s(text, _countof(text), L"read %llX 2", (unsigned long long)(UINT_PTR)memory);
    command(text);
    check(!tui_state.status_error && wcscmp(tui_state.status_msg, L"00 00 ") == 0 &&
          tui_state.panel == PANEL_PROCESSES, "short reads still fit the status row");

    ScanValue value = {0};
    value.type = SCAN_TYPE_STRING;
    tui_state.string_enc = 1;
    check(tui_parse_scan_value(L"A\x03A9", &value) && value.width == 4 &&
          memcmp(value.bytes, "\x41\0\xA9\x03", 4) == 0, "UTF-16 copies Windows code units as little-endian bytes");
    addr_table_destroy(&tui_state.address_table);
    addr_table_init(&tui_state.address_table, &tui_state.target);
    scanner_session_destroy(&tui_state.scanner);
    scanner_session_init(&tui_state.scanner, &tui_state.target, SCAN_TYPE_I32);
}

static void seed_next_scan(int *candidate)
{
    scanner_session_destroy(&tui_state.scanner);
    scanner_session_init(&tui_state.scanner, &tui_state.target, SCAN_TYPE_I32);
    tui_state.scanner.results.count = 1000000;
    tui_state.scanner.results.addresses = malloc(tui_state.scanner.results.count * sizeof(unsigned long long));
    if (!tui_state.scanner.results.addresses) {
        check(0, "allocate timed scan fixture");
        tui_state.scanner.results.count = 0;
    }
    for (size_t i = 0; i < tui_state.scanner.results.count; i++) {
        tui_state.scanner.results.addresses[i] = (UINT_PTR)candidate;
    }
    tui_state.scanner.results.value_width = 4;
    memcpy(tui_state.scanner.results.value, candidate, 4);
    tui_state.scanner.results_type = SCAN_TYPE_I32;
    tui_state.scanner.has_results = 1;
}

static void test_scan_lifecycle(void)
{
    int candidate = 5;
    volatile int watched = 10;
    int locked = 77;
    addr_table_add(&tui_state.address_table, "locked", SCAN_TYPE_I32, (uintptr_t)&watched);
    addr_table_lock(&tui_state.address_table, 0, &locked);
    seed_next_scan(&candidate);
    tui_state.focus = FOCUS_COMMAND;
    command(L"next 6");
    check(tui_scan_is_running(), "next command returns while its worker runs");
    command(L"type u64");
    check(tui_state.status_error && tui_state.scanner.param.type == SCAN_TYPE_I32,
          "type change cannot mutate an active worker session");
    command(L"scan 8");
    check(tui_state.status_error && tui_scan_is_running(), "overlapping scan is rejected");

    ULONGLONG deadline = GetTickCount64() + 10000;
    int locked_during_scan = 0;
    while (tui_scan_is_running() && GetTickCount64() < deadline) {
        tui_poll_scan();
        if (!tui_scan_is_running()) break;
        watched = 10;
        tui_state.address_table_last_lock = 0;
        tick_address_table();
        if (watched == locked) locked_during_scan++;
        Sleep(10);
    }
    check(locked_during_scan > 0, "lock writes continue while the scan worker owns its results");
    check(!tui_scan_is_running() && tui_state.scanner.has_results &&
          tui_state.scanner.results.count == 0, "completed next scan publishes its result set");

    seed_next_scan(&candidate);
    command(L"next 6");
    tui_detach_target();
    check(!tui_scan_is_running() && !tui_state.attached && !tui_state.scanner_inited &&
          !tui_state.address_table.entries[0].locked,
          "detach cancels and joins before releasing target and scan state");
    tui_poll_scan();
    check(!tui_state.scanner.has_results, "cancelled work cannot republish results after detach");
}

int main(void)
{
    tui_state.target.handle = GetCurrentProcess();
    tui_state.target.pid = GetCurrentProcessId();
    tui_state.attached = TRUE;
    tui_state.scanner_inited = TRUE;
    tui_state.focus = FOCUS_COMMAND;
    addr_table_init(&tui_state.address_table, &tui_state.target);
    scanner_session_init(&tui_state.scanner, &tui_state.target, SCAN_TYPE_I32);
    test_selection_and_commands();
    test_scan_lifecycle();
    addr_table_destroy(&tui_state.address_table);
    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
