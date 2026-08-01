#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

#include "tui_internal.h"
#include "core/memory/memory.h"

/* Forward declarations — definitions at bottom of file. */
typedef void (*CommandHandler)(const wchar_t *args);

typedef struct {
    const wchar_t *prefix;
    CommandHandler handler;
} Command;

static void cmd_attach(const wchar_t *args);
static void cmd_read(const wchar_t *args);
static void cmd_write(const wchar_t *args);
static void cmd_scan(const wchar_t *args);
static void cmd_next(const wchar_t *args);
static void cmd_type(const wchar_t *args);
static void cmd_strenc(const wchar_t *args);
static void cmd_search(const wchar_t *args);
static void cmd_addentry(const wchar_t *args);
static void cmd_delentry(const wchar_t *args);
static void cmd_entrylabel(const wchar_t *args);
static void cmd_lockentry(const wchar_t *args);
static void cmd_unlockentry(const wchar_t *args);
static void cmd_saveentry(const wchar_t *args);
static void cmd_loadentry(const wchar_t *args);
static void cmd_hex(const wchar_t *args);
static void cmd_disasm(const wchar_t *args);
static const wchar_t *skip_spaces(const wchar_t *text);
static int parse_unsigned(const wchar_t *text, int base, unsigned long long maximum,
                          unsigned long long *value, const wchar_t **tail);
static int parse_index(const wchar_t *text, size_t count, size_t *index, const wchar_t **tail);
static int tail_is_empty(const wchar_t *text);
static int narrow_ascii(const wchar_t *text, char *output, size_t capacity);

static const Command commands[] = {
    { L"attach ", cmd_attach },
    { L"read ", cmd_read },
    { L"write ", cmd_write },
    { L"scan ", cmd_scan },
    { L"next ", cmd_next },
    { L"type ", cmd_type },
    { L"strenc ", cmd_strenc },
    { L"search ", cmd_search },
    { L"addentry ", cmd_addentry },
    { L"delentry ", cmd_delentry },
    { L"entrylabel ", cmd_entrylabel },
    { L"lockentry ", cmd_lockentry },
    { L"unlockentry ", cmd_unlockentry },
    { L"saveentry ", cmd_saveentry },
    { L"loadentry ", cmd_loadentry },
    { L"hex ", cmd_hex },
    { L"disasm ", cmd_disasm },
};

/* ---- Public API (order matches tui_internal.h) ---- */

void tui_exec_command(void)
{
    if (tui_state.cmd_len == 0) return;

    if (wcscmp(tui_state.cmd_buf, L"quit") == 0 || wcscmp(tui_state.cmd_buf, L"exit") == 0) {
        tui_state.running = FALSE;
        tui_state.cmd_len = 0;
        return;
    }

    if (wcscmp(tui_state.cmd_buf, L"detach") == 0) {
        if (tui_state.attached) {
            tui_detach_target();
            tui_set_status(L"Detached", FALSE);
        } else {
            tui_set_status(L"No process attached", TRUE);
        }
        tui_state.cmd_len = 0;
        return;
    }

    /* `search <name>` filters the Processes panel to entries whose image name
       contains <name> as a case-insensitive substring. `search` alone clears
       any active filter and shows the full list again. */
    if (wcscmp(tui_state.cmd_buf, L"search") == 0) {
        cmd_search(L"");
        tui_state.cmd_len = 0;
        return;
    }

    for (size_t i = 0; i < _countof(commands); i++) {
        size_t prefix_length = wcslen(commands[i].prefix);
        if (wcsncmp(tui_state.cmd_buf, commands[i].prefix, prefix_length) == 0) {
            commands[i].handler(tui_state.cmd_buf + prefix_length);
            tui_state.cmd_len = 0;
            return;
        }
    }

    if (wcscmp(tui_state.cmd_buf, L"help") == 0) {
        if (!tui_open_help()) tui_set_status(L"No help for this panel", TRUE);
        tui_state.cmd_len = 0;
        return;
    }

    wchar_t msg[STATUS_MSG_MAX];
    _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"Unknown command: %s", tui_state.cmd_buf);
    tui_set_status(msg, TRUE);
    tui_state.cmd_len = 0;
}

/* ---- Static helpers ---- */

static void cmd_attach(const wchar_t *args)
{
    unsigned long long parsed_pid = 0;
    const wchar_t *tail = NULL;
    if (!parse_unsigned(args, 10, UINT32_MAX, &parsed_pid, &tail) || parsed_pid == 0 ||
        !tail_is_empty(tail)) {
        tui_set_status(L"Invalid PID", TRUE);
    } else {
        tui_do_attach((DWORD)parsed_pid);
    }
}

static void cmd_read(const wchar_t *args)
{
    if (!tui_state.attached) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    unsigned long long size = 0;
    const wchar_t *tail = NULL;
    if (!parse_unsigned(args, 16, UINTPTR_MAX, &address, &tail) || address == 0 ||
        !parse_unsigned(tail, 10, 128, &size, &tail) || size == 0 || !tail_is_empty(tail)) {
        tui_set_status(L"usage: read <hex_address> <byte_count: 1-128>", TRUE);
        return;
    }

    unsigned char buf[128];
    PlatformError err = memory_read(&tui_state.target, address, buf, (size_t)size);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"read failed: %S", process_error_string(err));
        tui_set_status(msg, TRUE);
        return;
    }

    wchar_t result[STATUS_MSG_MAX];
    int pos = 0;
    for (size_t i = 0; i < (size_t)size; i++) {
        int written = swprintf_s(result + pos, _countof(result) - (size_t)pos, L"%02X ", buf[i]);
        if (written < 0) {
            tui_set_status(L"read display failed", TRUE);
            return;
        }
        pos += written;
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
    const wchar_t *p = NULL;
    if (!parse_unsigned(args, 16, UINTPTR_MAX, &address, &p) || address == 0) {
        tui_set_status(L"usage: write <hex_address> <byte> [byte ...]", TRUE);
        return;
    }

    unsigned char buf[128];
    size_t byte_count = 0;
    for (;;) {
        p = skip_spaces(p);
        if (!*p) break;
        int high = tui_hex_digit_value(p[0]);
        int low = tui_hex_digit_value(p[1]);
        if (byte_count == _countof(buf) || high < 0 || low < 0 ||
            (p[2] && p[2] != L' ' && p[2] != L'\t')) {
            tui_set_status(L"usage: write <hex_address> <byte> [byte ...]", TRUE);
            return;
        }
        buf[byte_count++] = (unsigned char)((high << 4) | low);
        p += 2;
    }
    if (byte_count == 0) {
        tui_set_status(L"usage: write <hex_address> <byte> [byte ...]", TRUE);
        return;
    }

    PlatformError err = memory_write(&tui_state.target, address, buf, byte_count);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"write failed: %S", process_error_string(err));
        tui_set_status(msg, TRUE);
        return;
    }

    wchar_t msg[256];
    swprintf_s(msg, _countof(msg), L"Wrote %llu byte(s) to 0x%llX",
               (unsigned long long)byte_count, address);
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
    PlatformError err = scanner_first_scan(&tui_state.scanner);
    if (err != PLATFORM_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"first scan failed: %S", process_error_string(err));
        tui_set_status(msg, TRUE);
        return;
    }

    wchar_t msg[160];
    if (tui_state.scanner.results.skipped_regions > 0) {
        swprintf_s(msg, _countof(msg), L"First scan: %llu hits; %llu volatile region(s) ignored",
                   (unsigned long long)tui_state.scanner.results.count,
                   (unsigned long long)tui_state.scanner.results.skipped_regions);
    } else {
        swprintf_s(msg, _countof(msg), L"First scan: %llu hits",
                   (unsigned long long)tui_state.scanner.results.count);
    }
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

    wchar_t msg[160];
    if (s->results.unreadable_candidates > 0) {
        swprintf_s(msg, _countof(msg), L"Next scan: %llu survivors; %llu unreadable candidate(s) removed",
                   (unsigned long long)s->results.count,
                   (unsigned long long)s->results.unreadable_candidates);
    } else {
        swprintf_s(msg, _countof(msg), L"Next scan: %llu survivors",
                   (unsigned long long)s->results.count);
    }
    tui_set_status(msg, FALSE);
}

static void cmd_type(const wchar_t *args)
{
    if (!tui_state.attached || !tui_state.scanner_inited) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    char type_name[16];
    size_t converted = 0;
    ScanType type;
    if (wcstombs_s(&converted, type_name, sizeof(type_name), args, _TRUNCATE) != 0 ||
        scanner_type_from_name(type_name, &type) != PLATFORM_OK) {
        tui_set_status(L"usage: type i8|i16|i32|i64|u8|u16|u32|u64|f32|f64|string|aob", TRUE);
        return;
    }

    /* A type change begins a fresh exact scan and releases prior hit storage. */
    scanner_session_destroy(&tui_state.scanner);
    scanner_session_init(&tui_state.scanner, &tui_state.target, type);

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

static void cmd_search(const wchar_t *args)
{
    /* Skip leading spaces so `search    chrome` works the same as
       `search chrome`. Trailing spaces are left as-is -- a trailing space is
       a legitimate part of a needle edge case, but trimming them too would
       break searching for image names ending in whitespace (none in
       practice), so we keep the simpler contract. */
    while (*args == L' ') args++;

    if (*args == L'\0') {
        tui_set_process_filter(L"");
        return;
    }

    tui_set_process_filter(args);

    /* If the user ran `search` from another panel, jump to the Processes
       panel so they see the filtered results instead of wondering where
       they went. We leave the focus alone (the command bar handlers will
       hand it back via Tab/Esc as usual). */
    if (tui_state.panel != PANEL_PROCESSES) {
        tui_state.panel = PANEL_PROCESSES;
        tui_state.sidebar_idx = PANEL_PROCESSES;
    }
}

static void cmd_addentry(const wchar_t *args)
{
    if (!tui_state.attached) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    const wchar_t *p = NULL;
    if (!parse_unsigned(args, 16, UINTPTR_MAX, &address, &p) || address == 0) {
        tui_set_status(L"usage: addentry <hex_addr> <type> <label>", TRUE);
        return;
    }

    p = skip_spaces(p);
    const wchar_t *type_start = p;
    while (*p && *p != L' ' && *p != L'\t') p++;
    size_t type_length = (size_t)(p - type_start);
    if (type_length == 0 || type_length >= 16) {
        tui_set_status(L"usage: addentry <hex_addr> <type> <label>", TRUE);
        return;
    }
    char type_name[16];
    for (size_t i = 0; i < type_length; i++) {
        if (type_start[i] > 127) {
            tui_set_status(L"Invalid address-table type", TRUE);
            return;
        }
        type_name[i] = (char)type_start[i];
    }
    type_name[type_length] = '\0';

    ScanType type;
    if (scanner_type_from_name(type_name, &type) != PLATFORM_OK || scanner_type_width(type) == 0) {
        tui_set_status(L"address-table type: i8|i16|i32|i64|u8|u16|u32|u64|f32|f64", TRUE);
        return;
    }

    const wchar_t *label_start = skip_spaces(p);
    char label[ADDR_ENTRY_LABEL_MAX];
    if (!narrow_ascii(label_start, label, sizeof(label))) {
        tui_set_status(L"label must be 1-63 ASCII characters without quotes or line breaks", TRUE);
        return;
    }
    if (addr_table_add(&tui_state.address_table, label, type, (uintptr_t)address) < 0) {
        tui_set_status(L"Failed to add entry", TRUE);
        return;
    }

    int index = (int)(tui_state.address_table.count - 1);
    tui_state.address_table_selected = index;
    wchar_t msg[STATUS_MSG_MAX];
    swprintf_s(msg, _countof(msg), L"Added entry %d: %S at 0x%llX", index, label, address);
    tui_set_status(msg, FALSE);
}

static void cmd_delentry(const wchar_t *args)
{
    size_t index = 0;
    const wchar_t *tail = NULL;
    if (!parse_index(args, tui_state.address_table.count, &index, &tail) || !tail_is_empty(tail)) {
        tui_set_status(L"usage: delentry <index>", TRUE);
        return;
    }
    if (addr_table_remove(&tui_state.address_table, index) != 0) {
        tui_set_status(L"Failed to remove entry", TRUE);
        return;
    }
    if (tui_state.address_table_selected >= (int)tui_state.address_table.count &&
        tui_state.address_table_selected > 0) tui_state.address_table_selected--;
    tui_set_status(L"Entry removed", FALSE);
}

static void cmd_entrylabel(const wchar_t *args)
{
    size_t index = 0;
    const wchar_t *tail = NULL;
    if (!parse_index(args, tui_state.address_table.count, &index, &tail)) {
        tui_set_status(L"usage: entrylabel <index> <new_label>", TRUE);
        return;
    }
    char label[ADDR_ENTRY_LABEL_MAX];
    if (!narrow_ascii(skip_spaces(tail), label, sizeof(label))) {
        tui_set_status(L"label must be 1-63 ASCII characters without quotes or line breaks", TRUE);
        return;
    }
    if (addr_table_rename(&tui_state.address_table, index, label) != 0) {
        tui_set_status(L"Failed to rename entry", TRUE);
        return;
    }
    wchar_t msg[STATUS_MSG_MAX];
    swprintf_s(msg, _countof(msg), L"Entry %llu renamed to \"%S\"", (unsigned long long)index, label);
    tui_set_status(msg, FALSE);
}

static void cmd_lockentry(const wchar_t *args)
{
    size_t index = 0;
    const wchar_t *tail = NULL;
    if (!parse_index(args, tui_state.address_table.count, &index, &tail)) {
        tui_set_status(L"usage: lockentry <index> <value>", TRUE);
        return;
    }
    const wchar_t *value_text = skip_spaces(tail);
    if (!*value_text) {
        tui_set_status(L"usage: lockentry <index> <value>", TRUE);
        return;
    }

    const AddrEntry *entry = &tui_state.address_table.entries[index];
    ScanValue value = {0};
    value.type = entry->type;
    if (!tui_parse_scan_value(value_text, &value)) {
        tui_set_status(L"Could not parse lock value for this entry's type", TRUE);
        return;
    }
    if (addr_table_lock(&tui_state.address_table, index, value.bytes) != 0) {
        tui_set_status(L"Failed to lock entry", TRUE);
        return;
    }
    wchar_t msg[STATUS_MSG_MAX];
    swprintf_s(msg, _countof(msg), L"Entry %llu locked", (unsigned long long)index);
    tui_set_status(msg, FALSE);
}

static void cmd_unlockentry(const wchar_t *args)
{
    size_t index = 0;
    const wchar_t *tail = NULL;
    if (!parse_index(args, tui_state.address_table.count, &index, &tail) || !tail_is_empty(tail)) {
        tui_set_status(L"usage: unlockentry <index>", TRUE);
        return;
    }
    if (addr_table_unlock(&tui_state.address_table, index) != 0) {
        tui_set_status(L"Failed to unlock entry", TRUE);
        return;
    }
    wchar_t msg[STATUS_MSG_MAX];
    swprintf_s(msg, _countof(msg), L"Entry %llu unlocked", (unsigned long long)index);
    tui_set_status(msg, FALSE);
}

static void cmd_saveentry(const wchar_t *args)
{
    const wchar_t *filepath = skip_spaces(args);
    if (!*filepath) {
        tui_set_status(L"usage: saveentry <filename>", TRUE);
        return;
    }
    AddrTableIoError error = addr_table_save(&tui_state.address_table, filepath);
    if (error != ADDR_TABLE_IO_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"Save failed: %S", addr_table_io_error_string(error));
        tui_set_status(msg, TRUE);
        return;
    }
    wchar_t msg[STATUS_MSG_MAX];
    swprintf_s(msg, _countof(msg), L"Saved %llu entries to \"%s\"",
               (unsigned long long)tui_state.address_table.count, filepath);
    tui_set_status(msg, FALSE);
}

static void cmd_loadentry(const wchar_t *args)
{
    const wchar_t *filepath = skip_spaces(args);
    if (!*filepath) {
        tui_set_status(L"usage: loadentry <filename>", TRUE);
        return;
    }
    AddrTableIoError error = addr_table_load(&tui_state.address_table, filepath);
    if (error != ADDR_TABLE_IO_OK) {
        wchar_t msg[256];
        swprintf_s(msg, _countof(msg), L"Load failed: %S", addr_table_io_error_string(error));
        tui_set_status(msg, TRUE);
        return;
    }
    tui_state.address_table_selected = 0;
    tui_state.address_table_scroll = 0;
    wchar_t msg[STATUS_MSG_MAX];
    swprintf_s(msg, _countof(msg), L"Loaded %llu entries from \"%s\"",
               (unsigned long long)tui_state.address_table.count, filepath);
    tui_set_status(msg, FALSE);
}
static void cmd_hex(const wchar_t *args)
{
    if (!tui_state.attached) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    const wchar_t *tail = NULL;
    if (!parse_unsigned(args, 16, UINTPTR_MAX, &address, &tail) || !tail_is_empty(tail)) {
        tui_set_status(L"usage: hex <hex_address>", TRUE);
        return;
    }

    tui_hexview_jump(address);
}

static void cmd_disasm(const wchar_t *args)
{
    if (!tui_state.attached) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }

    unsigned long long address = 0;
    const wchar_t *tail = NULL;
    if (!parse_unsigned(args, 16, UINTPTR_MAX, &address, &tail) || !tail_is_empty(tail)) {
        tui_set_status(L"usage: disasm <hex_address>", TRUE);
        return;
    }

    tui_disasm_jump(address);
}

static const wchar_t *skip_spaces(const wchar_t *text)
{
    while (*text == L' ' || *text == L'\t') text++;
    return text;
}

static int parse_unsigned(const wchar_t *text, int base, unsigned long long maximum,
                          unsigned long long *value, const wchar_t **tail)
{
    if (!text || !value || !tail) return 0;
    text = skip_spaces(text);
    if (!*text || *text == L'-' || *text == L'+') return 0;
    errno = 0;
    wchar_t *end = NULL;
    unsigned long long parsed = wcstoull(text, &end, base);
    if (errno == ERANGE || end == text || parsed > maximum ||
        (*end && *end != L' ' && *end != L'\t')) return 0;
    *value = parsed;
    *tail = end;
    return 1;
}

static int parse_index(const wchar_t *text, size_t count, size_t *index, const wchar_t **tail)
{
    unsigned long long parsed = 0;
    if (!parse_unsigned(text, 10, SIZE_MAX, &parsed, tail) || parsed >= count) return 0;
    *index = (size_t)parsed;
    return 1;
}

static int tail_is_empty(const wchar_t *text)
{
    return *skip_spaces(text) == L'\0';
}

static int narrow_ascii(const wchar_t *text, char *output, size_t capacity)
{
    if (!text || !output || capacity == 0) return 0;
    size_t length = wcslen(text);
    if (length == 0 || length >= capacity) return 0;
    for (size_t i = 0; i < length; i++) {
        if (text[i] > 127 || text[i] == L'"' || text[i] == L'\r' || text[i] == L'\n') return 0;
        output[i] = (char)text[i];
    }
    output[length] = '\0';
    return 1;
}
