#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "tui/tui_internal.h"
#include "test/test.h"

TuiState tui_state;

static void run_command(const wchar_t *command)
{
    wcscpy_s(tui_state.cmd_buf, CMD_BUF_MAX, command);
    tui_state.cmd_len = (int)wcslen(command);
    tui_exec_command();
}

int main(void)
{
    process_target_init(&tui_state.target);
    tui_state.target.handle = GetCurrentProcess();
    tui_state.target.pid = GetCurrentProcessId();
    tui_state.attached = TRUE;
    check(addr_table_init(&tui_state.address_table, &tui_state.target), "command-test table initializes");
    tui_state.attached = FALSE;
    check(tui_next_wait_timeout(1000) == INFINITE,
          "detached TUI waits for input instead of busy-spinning");
    tui_state.attached = TRUE;
    tui_state.address_table_last_refresh = 1000;
    tui_state.address_table_last_lock = 1000;
    check(tui_next_wait_timeout(1025) == 25,
          "attached TUI waits until the nearest lock deadline");
    tui_state.panel = PANEL_HEXVIEW;
    tui_state.address_table_last_refresh = 2000;
    tui_state.address_table_last_lock = 2000;
    tui_state.hexview_last_refresh = 1000;
    check(tui_next_wait_timeout(1100) == 100,
          "Hex View keeps the idle loop awake for its visible-window refresh");
    tui_state.panel = PANEL_PROCESSES;

    volatile int watched = 10;
    check(addr_table_add(&tui_state.address_table, "watched", SCAN_TYPE_I32,
                         (uintptr_t)&watched) == 0,
          "command-test entry is added");
    int locked_value = 77;
    check(addr_table_lock(&tui_state.address_table, 0, &locked_value) == 0,
          "command-test entry is locked");

    run_command(L"delentry garbage");
    check(tui_state.address_table.count == 1, "garbage delentry cannot remove entry zero");
    run_command(L"delentry 0junk");
    check(tui_state.address_table.count == 1, "trailing junk cannot remove entry zero");
    run_command(L"unlockentry garbage");
    check(tui_state.address_table.entries[0].locked, "garbage unlockentry cannot unlock entry zero");

    wchar_t long_command[CMD_BUF_MAX];
    for (size_t i = 0; i < CMD_BUF_MAX - 1; i++) long_command[i] = L'x';
    long_command[CMD_BUF_MAX - 1] = L'\0';
    run_command(long_command);
    check(wcsncmp(tui_state.status_msg, L"Unknown command: ", 17) == 0,
          "long unknown command is reported without aborting");
    check(tui_state.cmd_len == 0, "unknown command clears the command buffer");

    run_command(L"search chrome");
    check(wcscmp(tui_state.process_filter, L"chrome") == 0 && tui_state.cmd_len == 0,
          "prefixed search applies a process filter and clears the command buffer");
    run_command(L"search");
    check(tui_state.process_filter[0] == L'\0' && tui_state.cmd_len == 0,
          "exact search clears a process filter and the command buffer");

    unsigned char bytes[2] = {0};
    wchar_t write_command[128];
    swprintf_s(write_command, sizeof(write_command) / sizeof(write_command[0]), L"write %llX 90 91",
               (unsigned long long)(UINT_PTR)bytes);
    run_command(write_command);
    check(bytes[0] == 0x90 && bytes[1] == 0x91,
          "write accepts documented whitespace-separated byte pairs");

    wchar_t invalid_write[128];
    swprintf_s(invalid_write, sizeof(invalid_write) / sizeof(invalid_write[0]), L"write %llX 9091",
               (unsigned long long)(UINT_PTR)bytes);
    run_command(invalid_write);
    check(tui_state.status_error, "undocumented contiguous write bytes are rejected");

    run_command(L"read 1234 129");
    check(tui_state.status_error && tui_state.cmd_len == 0,
          "read rejects counts larger than the display contract and clears the command buffer");

    run_command(L"hex 0");
    check(tui_state.panel == PANEL_HEXVIEW && tui_state.hexview_address == 0,
          "hex command opens the Hex View at address zero");
    run_command(L"hex 100junk");
    check(tui_state.status_error, "hex command rejects a trailing address suffix");

    run_command(L"disasm 0");
    check(tui_state.panel == PANEL_DISASM && tui_state.disasm_address == 0,
          "disasm command opens the Disasm panel at address zero");
    run_command(L"disasm 100junk");
    check(tui_state.status_error, "disasm command rejects a trailing address suffix");

    tui_state.attached = FALSE;
    run_command(L"hex 1234");
    check(tui_state.status_error, "hex command requires an attached process");
    tui_state.attached = TRUE;

    ScanValue value = {0};
    value.type = SCAN_TYPE_U32;
    check(!tui_parse_scan_value(L"-1", &value), "unsigned scan value rejects negatives");
    check(!tui_parse_scan_value(L"10junk", &value), "numeric scan value rejects trailing junk");
    check(tui_parse_scan_value(L"10", &value), "strict numeric scan value accepts a complete token");

    value = (ScanValue){0};
    value.type = SCAN_TYPE_AOB;
    check(tui_parse_scan_value(L"48 8B 10 90", &value) && value.width == 4 &&
          value.bytes[0] == 0x48 && value.bytes[1] == 0x8B &&
          value.bytes[2] == 0x10 && value.bytes[3] == 0x90,
          "AOB scan value accepts exact byte pairs");
    check(!tui_parse_scan_value(L"48 ?? 10 90", &value),
          "AOB scan value rejects wildcard byte pairs");

    run_command(L"delentry 0");
    check(tui_state.address_table.count == 0, "valid delentry still removes the selected entry");
    addr_table_destroy(&tui_state.address_table);
    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
