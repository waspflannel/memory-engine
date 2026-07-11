#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

#include "tui_internal.h"
#include "core/memory/memory.h"

/* Command-prefix lengths, tied to the literals in tui_exec_command by name and
   value: the number is the wide-char length of the corresponding L"<verb> ". */
#define CMD_ATTACH_PREFIX 7  /* length of L"attach " */
#define CMD_READ_PREFIX   5  /* length of L"read "   */
#define CMD_WRITE_PREFIX  6  /* length of L"write "  */
#define CMD_SCAN_PREFIX   5  /* length of L"scan "   */
#define CMD_NEXT_PREFIX   5  /* length of L"next "   */
#define CMD_TYPE_PREFIX   5  /* length of L"type "   */
#define CMD_STRENC_PREFIX 7  /* length of L"strenc " */

/* Forward declarations — definitions at bottom of file. */
static void cmd_read(const wchar_t *args);
static void cmd_write(const wchar_t *args);
static void cmd_scan(const wchar_t *args);
static void cmd_next(const wchar_t *args);
static void cmd_type(const wchar_t *args);
static void cmd_strenc(const wchar_t *args);

/* ---- Public API (order matches tui_internal.h) ---- */

void tui_exec_command(void)
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
            tui_set_status(L"Invalid PID", TRUE);
        } else {
            tui_do_attach(pid);
        }
        tui_state.cmd_len = 0;
        return;
    }

    if (wcscmp(tui_state.cmd_buf, L"detach") == 0) {
        if (tui_state.attached) {
            if (tui_state.scanner_inited) {
                scanner_session_destroy(&tui_state.scanner);
                tui_state.scanner_inited = FALSE;
            }
            process_detach(&tui_state.target);
            tui_state.attached = FALSE;
            tui_set_status(L"Detached", FALSE);
        } else {
            tui_set_status(L"No process attached", TRUE);
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

    if (wcsncmp(tui_state.cmd_buf, L"type ", CMD_TYPE_PREFIX) == 0) {
        cmd_type(tui_state.cmd_buf + CMD_TYPE_PREFIX);
        tui_state.cmd_len = 0;
        return;
    }

    if (wcsncmp(tui_state.cmd_buf, L"strenc ", CMD_STRENC_PREFIX) == 0) {
        cmd_strenc(tui_state.cmd_buf + CMD_STRENC_PREFIX);
        tui_state.cmd_len = 0;
        return;
    }

    if (wcscmp(tui_state.cmd_buf, L"help") == 0) {
        const HelpBook *book = tui_help_book_for_panel(tui_state.panel);
        if (!book) {
            tui_set_status(L"No help for this panel", TRUE);
        } else {
            tui_state.help_book = book;
            tui_state.help_open = 1;
            tui_state.help_tab = 0;
            tui_state.help_scroll = 0;
        }
        tui_state.cmd_len = 0;
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, _countof(msg), L"Unknown command: %s", tui_state.cmd_buf);
    tui_set_status(msg, TRUE);
    tui_state.cmd_len = 0;
}

/* ---- Static helpers ---- */

static void cmd_read(const wchar_t *args)
{
    if (!tui_state.attached) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    int size = 0;
    if (swscanf_s(args, L"%llx %d", &address, &size) != 2 || size <= 0 || size > 512) {
        tui_set_status(L"usage: read <hex_address> <size_in_bytes>", TRUE);
        return;
    }

    unsigned char buf[512];
    PlatformError err = memory_read(&tui_state.target, address, buf, (size_t)size);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"read failed: %S", process_error_string(err));
        tui_set_status(msg, TRUE);
        return;
    }

    wchar_t result[512];
    int pos = 0;
    for (int i = 0; i < size && pos < 500; i++) {
        pos += swprintf_s(result + pos, 512 - pos, L"%02X ", buf[i]);
    }
    tui_set_status(result, FALSE);
}

static void cmd_write(const wchar_t *args)
{
    if (!tui_state.attached) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    wchar_t hex[256] = {0};
    if (swscanf_s(args, L"%llx %s", &address, hex, (unsigned int)(sizeof(hex) / sizeof(wchar_t))) != 2) {
        tui_set_status(L"usage: write <hex_address> <hex_bytes>", TRUE);
        return;
    }

    unsigned char buf[128];
    int hex_len = (int)wcslen(hex);
    int byte_count = hex_len / 2;
    if (byte_count == 0 || byte_count > 128 || hex_len % 2 != 0) {
        tui_set_status(L"invalid hex string -- even number of hex chars required", TRUE);
        return;
    }

    for (int i = 0; i < hex_len; i++) {
        wchar_t c = hex[i];
        if (!((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f'))) {
            tui_set_status(L"invalid hex string -- non-hex characters found", TRUE);
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
        tui_set_status(msg, TRUE);
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, _countof(msg), L"Wrote %d byte(s) to 0x%llX", byte_count, address);
    tui_set_status(msg, FALSE);
}

static void cmd_scan(const wchar_t *args)
{
    if (!tui_state.attached || !tui_state.scanner_inited) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    if (!tui_parse_scan_value(args, &tui_state.scanner.param)) {
        tui_set_status(L"usage: scan <value>", TRUE);
        return;
    }
    tui_state.scanner.mode = SCAN_MODE_EXACT;

    PlatformError err = scanner_first_scan(&tui_state.scanner);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"first scan failed: %S", process_error_string(err));
        tui_set_status(msg, TRUE);
        return;
    }

    wchar_t msg[128];
    swprintf_s(msg, _countof(msg), L"First scan: %llu hits",
               (unsigned long long)tui_state.scanner.results.count);
    tui_set_status(msg, FALSE);
}

static void cmd_next(const wchar_t *args)
{
    if (!tui_state.attached || !tui_state.scanner_inited) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }
    if (!tui_state.scanner.has_results) {
        tui_set_status(L"Run `scan <value>` first", TRUE);
        return;
    }

    ScanSession *s = &tui_state.scanner;

    if (!tui_parse_scan_value(args, &s->param)) {
        tui_set_status(L"usage: next <value>  (could not parse for current type)", TRUE);
        return;
    }

    PlatformError err = scanner_next_scan(s);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"next scan failed: %S", process_error_string(err));
        tui_set_status(msg, TRUE);
        return;
    }

    wchar_t msg[128];
    swprintf_s(msg, _countof(msg), L"Next scan: %llu survivors",
               (unsigned long long)s->results.count);
    tui_set_status(msg, FALSE);
}

static void cmd_type(const wchar_t *args)
{
    if (!tui_state.attached || !tui_state.scanner_inited) {
        tui_set_status(L"No process attached", TRUE);
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
        tui_set_status(L"usage: type i8|i16|i32|i64|u8|u16|u32|u64|f32|f64|string|aob", TRUE);
        return;
    }

    /* Re-init for the new type: drops any prior result set and resets mode to
       exact (a fresh type starts a fresh scan). The borrowed target pointer
       is the same field in tui_state, so keep it. */
    scanner_session_init(&tui_state.scanner, &tui_state.target, type, SCAN_MODE_EXACT);

    wchar_t msg[64];
    swprintf_s(msg, _countof(msg), L"Type: %s", tui_scan_type_name(type));
    tui_set_status(msg, FALSE);
}

static void cmd_strenc(const wchar_t *args)
{
    if (wcscmp(args, L"ascii") == 0) {
        tui_state.string_enc = 0;
        tui_set_status(L"String encoding: ASCII", FALSE);
    } else if (wcscmp(args, L"utf16") == 0) {
        tui_state.string_enc = 1;
        tui_set_status(L"String encoding: UTF-16LE", FALSE);
    } else {
        tui_set_status(L"usage: strenc ascii|utf16", TRUE);
    }
}