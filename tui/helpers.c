#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#include "tui_internal.h"

/* Forward declarations — definitions at bottom of file. */
static int parse_aob_value(const wchar_t *args, ScanValue *out);
static int parse_string_value(const wchar_t *args, ScanValue *out);
static int tail_is_empty(const wchar_t *text);
static int wcsstr_icase(const wchar_t *hay, const wchar_t *needle);
static void tui_rebuild_process_view(void);

/* ---- Public API (order matches tui_internal.h) ---- */

void tui_set_status(const wchar_t *msg, int is_error)
{
    wcsncpy_s(tui_state.status_msg, STATUS_MSG_MAX, msg, _TRUNCATE);
    tui_state.status_error = is_error;
    tui_state.status_ticks = GetTickCount64();
}

int tui_refresh_process_list(void)
{
    ProcessEntry *processes = NULL;
    unsigned int process_count = 0;
    PlatformError err = process_list(&processes, &process_count);
    if (err != PLATFORM_OK) {
        wchar_t message[256];
        swprintf_s(message, _countof(message), L"Failed to list processes: %S", process_error_string(err));
        tui_set_status(message, TRUE);
        return 0;
    }

    process_free_list(tui_state.processes);
    tui_state.processes = processes;
    tui_state.process_count = process_count;
    tui_state.selected_process = 0;
    tui_state.process_scroll = 0;
    tui_rebuild_process_view();
    return 1;
}

void tui_set_process_filter(const wchar_t *needle)
{
    wcsncpy_s(tui_state.process_filter, PROCESS_NAME_MAX, needle, _TRUNCATE);
    tui_state.selected_process = 0;
    tui_state.process_scroll = 0;
    tui_rebuild_process_view();

    if (tui_state.process_filter[0] == L'\0') {
        tui_set_status(L"Filter cleared", FALSE);
        return;
    }
    if (tui_state.process_view_count == 0) {
        wchar_t msg[PROCESS_NAME_MAX + 32];
        swprintf_s(msg, _countof(msg), L"No processes match \"%s\"", needle);
        tui_set_status(msg, TRUE);
        return;
    }
    wchar_t msg[PROCESS_NAME_MAX + 64];
    swprintf_s(msg, _countof(msg), L"Filter \"%s\": %u of %u processes",
               needle, tui_state.process_view_count, tui_state.process_count);
    tui_set_status(msg, FALSE);
}

DWORD tui_next_wait_timeout(ULONGLONG now)
{
    if (!tui_state.attached) return INFINITE;
    ULONGLONG refresh_due = tui_state.address_table_last_refresh + ADDR_TABLE_REFRESH_INTERVAL_MS;
    ULONGLONG lock_due = tui_state.address_table_last_lock + ADDR_TABLE_LOCK_INTERVAL_MS;
    ULONGLONG due = refresh_due < lock_due ? refresh_due : lock_due;
    if (tui_state.panel == PANEL_HEXVIEW) {
        ULONGLONG hexview_due = tui_state.hexview_last_refresh + HEXVIEW_REFRESH_INTERVAL_MS;
        if (hexview_due < due) due = hexview_due;
    }
    return now >= due ? 0 : (DWORD)(due - now);
}

void tui_detach_target(void)
{
    if (tui_state.scanner_inited) {
        scanner_session_destroy(&tui_state.scanner);
        tui_state.scanner_inited = FALSE;
    }
    addr_table_set_target(&tui_state.address_table, NULL);
    process_detach(&tui_state.target);
    tui_state.attached = FALSE;
    tui_state.address_table_last_refresh = 0;
    tui_state.address_table_last_lock = 0;
    tui_state.hexview_byte_count = 0;
    tui_state.hexview_window_valid = FALSE;
    tui_state.hexview_last_refresh = 0;
    tui_state.hexview_high_nibble = -1;
    memset(tui_state.hexview_readable, 0, sizeof(tui_state.hexview_readable));
}

int tui_do_attach(DWORD pid)
{
    if (tui_state.attached) tui_detach_target();

    process_enable_privilege();

    PlatformError err = process_attach(pid, &tui_state.target);
    if (err != PLATFORM_OK) {
        wchar_t msg[512];
        swprintf_s(msg, _countof(msg), L"Failed to attach to PID %u: %S", pid, process_error_string(err));
        tui_set_status(msg, TRUE);
        return 0;
    }

    tui_state.attached = TRUE;
    scanner_session_init(&tui_state.scanner, &tui_state.target, SCAN_TYPE_I32);
    tui_state.scanner_inited = TRUE;

    addr_table_set_target(&tui_state.address_table, &tui_state.target);
    tui_state.address_table_last_refresh = 0;
    tui_state.address_table_last_lock = 0;
    tui_state.scanner_selected_index = 0;
    tui_state.hexview_address = tui_state.target.base;
    tui_state.hexview_cursor = 0;
    tui_state.hexview_byte_count = 0;
    tui_state.hexview_window_valid = FALSE;
    tui_state.hexview_last_refresh = 0;
    tui_state.hexview_high_nibble = -1;
    memset(tui_state.hexview_readable, 0, sizeof(tui_state.hexview_readable));

    wchar_t msg[PROCESS_NAME_MAX + 32];
    swprintf_s(msg, _countof(msg), L"Attached to %s (PID %u)", tui_state.target.name, pid);
    tui_set_status(msg, FALSE);
    return 1;
}

void tui_attach_to_selected(void)
{
    if (!tui_state.processes || tui_state.process_view_count == 0) return;
    if ((unsigned int)tui_state.selected_process >= tui_state.process_view_count) return;

    unsigned int idx = tui_state.process_view[tui_state.selected_process];
    tui_do_attach(tui_state.processes[idx].pid);
}

void tui_hexview_jump(unsigned long long address)
{
    tui_state.hexview_address = address;
    tui_state.hexview_cursor = 0;
    tui_state.hexview_byte_count = 0;
    tui_state.hexview_window_valid = FALSE;
    tui_state.hexview_last_refresh = 0;
    tui_state.hexview_high_nibble = -1;
    memset(tui_state.hexview_readable, 0, sizeof(tui_state.hexview_readable));
    tui_state.panel = PANEL_HEXVIEW;
    tui_state.sidebar_idx = PANEL_HEXVIEW;
}

const wchar_t *tui_scan_type_name(ScanType type)
{
    static wchar_t name[16];
    const char *canonical = scanner_type_name(type);
    size_t converted = 0;
    if (!canonical || mbstowcs_s(&converted, name, _countof(name), canonical, _TRUNCATE) != 0) return L"?";
    return name;
}

int tui_parse_scan_value(const wchar_t *args, ScanValue *out)
{
    if (!args || !out) return 0;
    wchar_t *end = NULL;
    const wchar_t *trimmed = args;
    while (*trimmed == L' ' || *trimmed == L'\t') trimmed++;
    errno = 0;

    switch (out->type) {
    case SCAN_TYPE_I8: {
        long long parsed = wcstoll(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end) || parsed < INT8_MIN || parsed > INT8_MAX) return 0;
        int8_t value = (int8_t)parsed;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_I16: {
        long long parsed = wcstoll(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end) || parsed < INT16_MIN || parsed > INT16_MAX) return 0;
        int16_t value = (int16_t)parsed;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_I32: {
        long long parsed = wcstoll(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end) || parsed < INT32_MIN || parsed > INT32_MAX) return 0;
        int32_t value = (int32_t)parsed;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_I64: {
        long long value = wcstoll(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end)) return 0;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_U8: {
        if (*trimmed == L'-') return 0;
        unsigned long long parsed = wcstoull(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end) || parsed > UINT8_MAX) return 0;
        uint8_t value = (uint8_t)parsed;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_U16: {
        if (*trimmed == L'-') return 0;
        unsigned long long parsed = wcstoull(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end) || parsed > UINT16_MAX) return 0;
        uint16_t value = (uint16_t)parsed;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_U32: {
        if (*trimmed == L'-') return 0;
        unsigned long long parsed = wcstoull(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end) || parsed > UINT32_MAX) return 0;
        uint32_t value = (uint32_t)parsed;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_U64: {
        if (*trimmed == L'-') return 0;
        unsigned long long value = wcstoull(args, &end, 10);
        if (errno == ERANGE || end == args || !tail_is_empty(end)) return 0;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_F32: {
        float value = wcstof(args, &end);
        if (errno == ERANGE || end == args || !tail_is_empty(end)) return 0;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_F64: {
        double value = wcstod(args, &end);
        if (errno == ERANGE || end == args || !tail_is_empty(end)) return 0;
        return scanner_value_set(out, out->type, &value, sizeof(value)) == PLATFORM_OK;
    }
    case SCAN_TYPE_STRING: return parse_string_value(args, out);
    case SCAN_TYPE_AOB:    return parse_aob_value(args, out);
    default:               return 0;
    }
}

int tui_hex_digit_value(wchar_t c)
{
    if (c >= L'0' && c <= L'9') return (int)(c - L'0');
    if (c >= L'a' && c <= L'f') return (int)(c - L'a') + 10;
    if (c >= L'A' && c <= L'F') return (int)(c - L'A') + 10;
    return -1;
}

/* ---- Static helpers ---- */

static int tail_is_empty(const wchar_t *text)
{
    while (*text == L' ' || *text == L'\t') text++;
    return *text == L'\0';
}

static int parse_aob_value(const wchar_t *args, ScanValue *out)
{
    unsigned char bytes[SCAN_VALUE_MAX];
    size_t n = 0;

    const wchar_t *p = args;
    while (*p) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;

        if (n >= SCAN_VALUE_MAX) return 0;

        int high = tui_hex_digit_value(p[0]);
        int low = tui_hex_digit_value(p[1]);
        if (high < 0 || low < 0) return 0;
        bytes[n++] = (unsigned char)((high << 4) | low);
        p += 2;
        if (*p && *p != L' ' && *p != L'\t') return 0;
    }

    if (n == 0) return 0;

    return scanner_value_set(out, SCAN_TYPE_AOB, bytes, n) == PLATFORM_OK;
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

    return scanner_value_set(out, SCAN_TYPE_STRING, bytes, n) == PLATFORM_OK;
}

static int wcsstr_icase(const wchar_t *hay, const wchar_t *needle)
{
    if (!needle || !*needle) return 1;
    size_t length = wcslen(needle);
    for (const wchar_t *start = hay; *start; start++)
        if (_wcsnicmp(start, needle, length) == 0) return 1;
    return 0;
}

/* Rebuilds `process_view` from `processes` using the current `process_filter`
   substring. Empty filter -> identity view (every process shown). The caller
   is responsible for resetting selection/scroll -- this only touches the view
   array so an F5 refresh can reuse it without dropping the filter. */
static void tui_rebuild_process_view(void)
{
    if (tui_state.process_view) {
        free(tui_state.process_view);
        tui_state.process_view = NULL;
    }
    tui_state.process_view_count = 0;

    if (tui_state.process_count == 0) return;

    tui_state.process_view =
        malloc(tui_state.process_count * sizeof(unsigned int));
    if (!tui_state.process_view) {
        tui_set_status(L"Out of memory building process filter", TRUE);
        return;
    }

    int has_filter = (tui_state.process_filter[0] != L'\0');
    unsigned int n = 0;
    for (unsigned int i = 0; i < tui_state.process_count; i++) {
        if (has_filter && !wcsstr_icase(tui_state.processes[i].name,
                                        tui_state.process_filter)) {
            continue;
        }
        tui_state.process_view[n++] = i;
    }
    tui_state.process_view_count = n;

    /* If narrowing dropped the selection (or the list grew on refresh so the
       selection points past the new view), clamp it back inside. */
    if ((unsigned int)tui_state.selected_process > tui_state.process_view_count) {
        tui_state.selected_process = 0;
        tui_state.process_scroll = 0;
    }
    if (tui_state.selected_process > 0 &&
        (unsigned int)tui_state.selected_process >= tui_state.process_view_count) {
        tui_state.selected_process =
            tui_state.process_view_count > 0
                ? (int)tui_state.process_view_count - 1 : 0;
    }
}
