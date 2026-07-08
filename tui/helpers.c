#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

#include "tui_internal.h"

/* Forward declarations — definitions at bottom of file. */
static int parse_aob_value(const wchar_t *args, ScanValue *out);
static int parse_string_value(const wchar_t *args, ScanValue *out);
static void set_int_value(ScanValue *v, ScanType type, int x);
static void set_uint_value(ScanValue *v, ScanType type, unsigned int x);
static int is_hex_wchar(wchar_t c);
static int hex_wchar_value(wchar_t c);

/* ---- Public API (order matches tui_internal.h) ---- */

void tui_set_status(const wchar_t *msg, int is_error)
{
    wcsncpy_s(tui_state.status_msg, STATUS_MSG_MAX, msg, _TRUNCATE);
    tui_state.status_error = is_error;
    tui_state.status_ticks = GetTickCount64();
}

void tui_refresh_process_list(void)
{
    if (tui_state.processes) {
        process_free_list(tui_state.processes);
        tui_state.processes = NULL;
    }
    tui_state.process_count = 0;
    tui_state.selected_process = 0;
    tui_state.process_scroll = 0;

    PlatformError err = process_list(&tui_state.processes, &tui_state.process_count);
    if (err != PLATFORM_OK) {
        tui_set_status(L"Failed to list processes", TRUE);
    }
}

int tui_do_attach(DWORD pid)
{
    if (tui_state.attached) {
        if (tui_state.scanner_inited) {
            scanner_session_destroy(&tui_state.scanner);
            tui_state.scanner_inited = FALSE;
        }
        process_detach(&tui_state.target);
        tui_state.attached = FALSE;
    }

    process_enable_privilege();

    PlatformError err = process_attach(pid, &tui_state.target);
    if (err != PLATFORM_OK) {
        wchar_t msg[512];
        swprintf_s(msg, _countof(msg), L"Failed to attach to PID %u: %S", pid, process_error_string(err));
        tui_set_status(msg, TRUE);
        return 0;
    }

    tui_state.attached = TRUE;
    scanner_session_init(&tui_state.scanner, &tui_state.target, SCAN_TYPE_I32, SCAN_MODE_EXACT);
    tui_state.scanner_inited = TRUE;
    wchar_t msg[PROCESS_NAME_MAX + 32];
    swprintf_s(msg, _countof(msg), L"Attached to %s (PID %u)", tui_state.target.name, pid);
    tui_set_status(msg, FALSE);
    return 1;
}

void tui_attach_to_selected(void)
{
    if (!tui_state.processes || tui_state.process_count == 0) return;
    if ((unsigned int)tui_state.selected_process >= tui_state.process_count) return;

    tui_do_attach(tui_state.processes[tui_state.selected_process].pid);
}

const wchar_t *tui_scan_type_name(ScanType type)
{
    switch (type) {
    case SCAN_TYPE_I32:    return L"i32";
    case SCAN_TYPE_I8:     return L"i8";
    case SCAN_TYPE_I16:    return L"i16";
    case SCAN_TYPE_I64:    return L"i64";
    case SCAN_TYPE_U8:     return L"u8";
    case SCAN_TYPE_U16:    return L"u16";
    case SCAN_TYPE_U32:    return L"u32";
    case SCAN_TYPE_U64:    return L"u64";
    case SCAN_TYPE_F32:    return L"f32";
    case SCAN_TYPE_F64:    return L"f64";
    case SCAN_TYPE_STRING: return L"string";
    case SCAN_TYPE_AOB:    return L"aob";
    default:               return L"?";
    }
}

const wchar_t *tui_scan_mode_name(ScanMode mode)
{
    switch (mode) {
    case SCAN_MODE_EXACT:        return L"exact";
    case SCAN_MODE_CHANGED:      return L"changed";
    case SCAN_MODE_UNCHANGED:    return L"unchanged";
    case SCAN_MODE_INCREASED:    return L"increased";
    case SCAN_MODE_DECREASED:    return L"decreased";
    case SCAN_MODE_INCREASED_BY: return L"increasedby";
    case SCAN_MODE_DECREASED_BY: return L"decreasedby";
    case SCAN_MODE_BETWEEN:      return L"between";
    case SCAN_MODE_UNKNOWN_INITIAL: return L"unknown";
    default:                     return L"?";
    }
}

int tui_parse_scan_value(const wchar_t *args, ScanValue *out)
{
    switch (out->type) {
    case SCAN_TYPE_I8:
    case SCAN_TYPE_I16:
    case SCAN_TYPE_I32: {
        int x = 0;
        if (swscanf_s(args, L"%d", &x) != 1) return 0;
        set_int_value(out, out->type, x);
        return 1;
    }
    case SCAN_TYPE_I64: {
        long long x = 0;
        if (swscanf_s(args, L"%lld", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_U8:
    case SCAN_TYPE_U16:
    case SCAN_TYPE_U32: {
        unsigned int x = 0;
        if (swscanf_s(args, L"%u", &x) != 1) return 0;
        set_uint_value(out, out->type, x);
        return 1;
    }
    case SCAN_TYPE_U64: {
        unsigned long long x = 0;
        if (swscanf_s(args, L"%llu", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_F32: {
        float x = 0.0f;
        if (swscanf_s(args, L"%f", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_F64: {
        double x = 0.0;
        if (swscanf_s(args, L"%lf", &x) != 1) return 0;
        scanner_value_set(out, out->type, &x, sizeof(x));
        return 1;
    }
    case SCAN_TYPE_STRING: return parse_string_value(args, out);
    case SCAN_TYPE_AOB:    return parse_aob_value(args, out);
    default:               return 0;
    }
}

int tui_parse_two_numeric(const wchar_t *args, ScanType type, ScanValue *lo, ScanValue *hi)
{
    switch (type) {
    case SCAN_TYPE_I8:
    case SCAN_TYPE_I16:
    case SCAN_TYPE_I32: {
        int a, b;
        if (swscanf_s(args, L"%d %d", &a, &b) != 2) return 0;
        set_int_value(lo, type, a);
        set_int_value(hi, type, b);
        return 1;
    }
    case SCAN_TYPE_I64: {
        long long a, b;
        if (swscanf_s(args, L"%lld %lld", &a, &b) != 2) return 0;
        scanner_value_set(lo, type, &a, sizeof(a));
        scanner_value_set(hi, type, &b, sizeof(b));
        return 1;
    }
    case SCAN_TYPE_U8:
    case SCAN_TYPE_U16:
    case SCAN_TYPE_U32: {
        unsigned int a, b;
        if (swscanf_s(args, L"%u %u", &a, &b) != 2) return 0;
        set_uint_value(lo, type, a);
        set_uint_value(hi, type, b);
        return 1;
    }
    case SCAN_TYPE_U64: {
        unsigned long long a, b;
        if (swscanf_s(args, L"%llu %llu", &a, &b) != 2) return 0;
        scanner_value_set(lo, type, &a, sizeof(a));
        scanner_value_set(hi, type, &b, sizeof(b));
        return 1;
    }
    case SCAN_TYPE_F32: {
        float a, b;
        if (swscanf_s(args, L"%f %f", &a, &b) != 2) return 0;
        scanner_value_set(lo, type, &a, sizeof(a));
        scanner_value_set(hi, type, &b, sizeof(b));
        return 1;
    }
    case SCAN_TYPE_F64: {
        double a, b;
        if (swscanf_s(args, L"%lf %lf", &a, &b) != 2) return 0;
        scanner_value_set(lo, type, &a, sizeof(a));
        scanner_value_set(hi, type, &b, sizeof(b));
        return 1;
    }
    default:
        return 0;   /* string/AOB: between unsupported */
    }
}

/* ---- Static helpers ---- */

static int is_hex_wchar(wchar_t c)
{
    return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f');
}

static int hex_wchar_value(wchar_t c)
{
    if (c >= L'0' && c <= L'9') return (int)(c - L'0');
    if (c >= L'A' && c <= L'F') return (int)(c - L'A') + 10;
    return (int)(c - L'a') + 10;
}

static int parse_aob_value(const wchar_t *args, ScanValue *out)
{
    unsigned char bytes[SCAN_VALUE_MAX];
    unsigned char wild[SCAN_VALUE_MAX];
    size_t n = 0;

    const wchar_t *p = args;
    while (*p) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;

        if (n >= SCAN_VALUE_MAX) return 0;

        if (p[0] == L'?' && p[1] == L'?') {
            wild[n] = 1;
            bytes[n] = 0;
            n++;
            p += 2;
        } else if (is_hex_wchar(p[0]) && is_hex_wchar(p[1])) {
            wild[n] = 0;
            bytes[n] = (unsigned char)((hex_wchar_value(p[0]) << 4) | hex_wchar_value(p[1]));
            n++;
            p += 2;
        } else {
            return 0;   /* malformed token */
        }
    }

    if (n == 0) return 0;

    scanner_value_set(out, SCAN_TYPE_AOB, bytes, n);
    scanner_value_set_wildcard(out, wild, n);
    return 1;
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

    scanner_value_set(out, SCAN_TYPE_STRING, bytes, n);
    return 1;
}

static void set_int_value(ScanValue *v, ScanType type, int x)
{
    if (type == SCAN_TYPE_I8)  { signed char t = (signed char)x; scanner_value_set(v, type, &t, 1); }
    else if (type == SCAN_TYPE_I16) { short t = (short)x;        scanner_value_set(v, type, &t, 2); }
    else                             { int t = x;                 scanner_value_set(v, type, &t, 4); }
}

static void set_uint_value(ScanValue *v, ScanType type, unsigned int x)
{
    if (type == SCAN_TYPE_U8) { unsigned char t = (unsigned char)x;  scanner_value_set(v, type, &t, 1); }
    else if (type == SCAN_TYPE_U16) { unsigned short t = (unsigned short)x; scanner_value_set(v, type, &t, 2); }
    else                            { unsigned int t = x;            scanner_value_set(v, type, &t, 4); }
}