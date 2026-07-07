#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/process/process.h"
#include "core/scanner/scanner.h"
#include "core/memory/memory.h"

/*
 * End-to-end scanner tests: spawn test_target.exe, attach, run real scans
 * against its published known values, and assert each type/mode/wildcard/
 * threading property from the phase-2 definition of done. This is the path
 * core_tests cannot cover (those run without an attached process). ctest
 * runs this test next to test_target.exe (CMake WORKING_DIRECTORY), so the
 * child resolves by bare executable name.
 */

static int failures = 0;

static void check(int cond, const char *msg)
{
    if (!cond) {
        failures++;
        printf("  FAIL: %s\n", msg);
    } else {
        printf("  ok: %s\n", msg);
    }
}

static int find_addr(const ScanResults *r, unsigned long long addr)
{
    for (size_t i = 0; i < r->count; i++) {
        if (r->addresses[i] == addr) return 1;
    }
    return 0;
}

static int find_value_at(const ScanResults *r, unsigned long long addr,
                         const void *expected, size_t width)
{
    for (size_t i = 0; i < r->count; i++) {
        if (r->addresses[i] == addr &&
            memcmp(r->values + i * r->value_width, expected, width) == 0) {
            return 1;
        }
    }
    return 0;
}

static int parse_addr(const char *buf, const char *name, unsigned long long *out)
{
    const char *p = strstr(buf, name);
    if (!p) return 0;
    const char *at = strchr(p, '@');
    if (!at) return 0;
    return sscanf_s(at + 1, " %llx", out) == 1;
}

int main(void)
{
    /* Spawn test_target.exe with captured stdout so we can parse the addresses
       of its published known values. The scanner can't attach to its own
       process (the platform layer forbids self-open), so this child carries
       the targets we scan against. */
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE out_r, out_w, in_r, in_w;
    if (!CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&in_r, &in_w, &sa, 0)) {
        printf("FAIL: CreatePipe\n");
        return 1;
    }
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(in_w,  HANDLE_FLAG_INHERIT, 0);  /* we keep in_w; the child blocks on in_r forever */

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    si.hStdInput = in_r;  /* inherited, write side stays alive with us -> child never hits EOF */
    PROCESS_INFORMATION pi = {0};

    WCHAR cmd[] = L"test_target.exe";
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("FAIL: cannot spawn test_target.exe (it must sit beside scanner_tests.exe)\n");
        CloseHandle(out_r); CloseHandle(out_w); CloseHandle(in_r); CloseHandle(in_w);
        return 1;
    }
    CloseHandle(out_w);  /* close our write end so reads terminate on EOF */
    CloseHandle(in_r);   /* child has its read end; we hold in_w */

    char banner[8192];
    size_t filled = 0;
    DWORD got;
    int saw_ascii = 0;
    while (filled < sizeof(banner) - 1) {
        if (!ReadFile(out_r, banner + filled, (DWORD)(sizeof(banner) - 1 - filled), &got, NULL) || got == 0) break;
        filled += got;
        banner[filled] = 0;
        if (strstr(banner, "target_ascii_string")) { saw_ascii = 1; break; }
    }
    banner[filled] = 0;
    if (!saw_ascii) {
        printf("FAIL: banner truncated (%zu bytes): %.400s\n", filled, banner);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(out_r);
        return 1;
    }

    unsigned int pid_int = 0;
    const char *pp = strstr(banner, "PID:");
    if (!pp || sscanf_s(pp, "PID: %u", &pid_int) != 1) {
        printf("FAIL: cannot parse PID\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(out_r);
        return 1;
    }
    DWORD pid = (DWORD)pid_int;

    unsigned long long health_addr = 0, speed_addr = 0, u32_addr = 0,
                         i64_addr = 0, name_addr = 0, ascii_addr = 0;
    parse_addr(banner, "target_health",         &health_addr);
    parse_addr(banner, "target_speed",          &speed_addr);
    parse_addr(banner, "target_counter_u32",    &u32_addr);
    parse_addr(banner, "target_counter_i64",    &i64_addr);
    parse_addr(banner, "target_name",           &name_addr);
    parse_addr(banner, "target_ascii_string",    &ascii_addr);
    if (!health_addr || !speed_addr || !u32_addr || !i64_addr || !name_addr || !ascii_addr) {
        printf("FAIL: banner address missing\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(out_r);
        return 1;
    }

    process_enable_privilege();
    Target target = {0};
    if (process_attach(pid, &target) != PLATFORM_OK) {
        printf("FAIL: attach to test_target (PID %u)\n", pid);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(out_r);
        return 1;
    }

    printf("--- T1: i32 exact first scan + threaded/single equality ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_I32, SCAN_MODE_EXACT);
        int v = 100;
        scanner_value_set(&s.param, SCAN_TYPE_I32, &v, sizeof(v));

        ScanRegion *regs = NULL;
        size_t nregs = 0;
        check(scanner_enumerate_regions(&target, &regs, &nregs) == PLATFORM_OK, "enumerate_regions ok");

        ScanResults single; scan_results_init(&single);
        check(scanner_scan_regions(&s, regs, nregs, &single) == PLATFORM_OK, "scanner_scan_regions (single) ok");

        check(scanner_first_scan(&s) == PLATFORM_OK, "threaded scanner_first_scan ok");

        check(s.results.count == single.count, "threaded count == single count");
        int eq = (s.results.count == single.count);
        for (size_t i = 0; eq && i < s.results.count; i++) {
            if (s.results.addresses[i] != single.addresses[i]) eq = 0;
        }
        check(eq, "threaded addresses == single addresses (in region order)");

        check(find_value_at(&s.results, health_addr, &v, sizeof(v)),
              "threaded results contain health_addr with value 100");
        check(find_value_at(&single, health_addr, &v, sizeof(v)),
              "single results contain health_addr with value 100");

        scanner_free_regions(regs);
        scan_results_free(&single);
        scanner_session_destroy(&s);
    }

    printf("--- T2: exact narrowing after a value change ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_I32, SCAN_MODE_EXACT);
        int v100 = 100;
        scanner_value_set(&s.param, SCAN_TYPE_I32, &v100, sizeof(v100));
        check(scanner_first_scan(&s) == PLATFORM_OK, "first scan for 100");

        int v50 = 50;
        check(memory_write(&target, health_addr, &v50, sizeof(v50)) == PLATFORM_OK, "write 50 to health_addr");
        scanner_value_set(&s.param, SCAN_TYPE_I32, &v50, sizeof(v50));
        check(scanner_next_scan(&s) == PLATFORM_OK, "next scan for 50");
        check(s.results.count > 0, "narrowing to 50 has survivors");
        check(find_addr(&s.results, health_addr), "health_addr survives narrowing to 50");

        int v25 = 25;
        memory_write(&target, health_addr, &v25, sizeof(v25));
        scanner_value_set(&s.param, SCAN_TYPE_I32, &v25, sizeof(v25));
        scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "health_addr survives a second narrowing to 25");

        scanner_session_destroy(&s);
    }

    printf("--- T3: unknown-initial first scan + the relative narrowing modes ---\n");
    {
        int v0 = 100; memory_write(&target, health_addr, &v0, sizeof(v0));

        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_I32, SCAN_MODE_UNKNOWN_INITIAL);
        s.mode = SCAN_MODE_UNKNOWN_INITIAL;
        check(scanner_first_scan(&s) == PLATFORM_OK, "unknown-initial first scan ok");
        check(s.results.count > 1000, "unknown-initial snapshots many candidates");

        int v99 = 99; memory_write(&target, health_addr, &v99, sizeof(v99));
        s.mode = SCAN_MODE_CHANGED; scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "CHANGED keeps health_addr");

        s.mode = SCAN_MODE_UNCHANGED; scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "UNCHANGED keeps health_addr after no further change");

        int v109 = 109; memory_write(&target, health_addr, &v109, sizeof(v109));
        s.mode = SCAN_MODE_INCREASED; scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "INCREASED keeps health_addr (99 -> 109)");

        int v90 = 90; memory_write(&target, health_addr, &v90, sizeof(v90));
        s.mode = SCAN_MODE_DECREASED; scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "DECREASED keeps health_addr (109 -> 90)");

        int v65 = 65; memory_write(&target, health_addr, &v65, sizeof(v65));
        int delta25 = 25;
        scanner_value_set(&s.param, SCAN_TYPE_I32, &delta25, sizeof(delta25));
        s.mode = SCAN_MODE_DECREASED_BY; scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "DECREASED_BY 25 keeps health_addr (90 -> 65)");

        int v90b = 90; memory_write(&target, health_addr, &v90b, sizeof(v90b));
        scanner_value_set(&s.param, SCAN_TYPE_I32, &delta25, sizeof(delta25));
        s.mode = SCAN_MODE_INCREASED_BY; scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "INCREASED_BY 25 keeps health_addr (65 -> 90)");

        int v85 = 85, lo = 80, hi = 100;
        memory_write(&target, health_addr, &v85, sizeof(v85));
        scanner_value_set(&s.param,  SCAN_TYPE_I32, &lo, sizeof(lo));
        scanner_value_set(&s.param2, SCAN_TYPE_I32, &hi, sizeof(hi));
        s.mode = SCAN_MODE_BETWEEN; scanner_next_scan(&s);
        check(find_addr(&s.results, health_addr), "BETWEEN 80..100 keeps health_addr (=85)");

        scanner_session_destroy(&s);
    }

    printf("--- T4: f32 spot check ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_F32, SCAN_MODE_EXACT);
        float v = 1.5f;
        scanner_value_set(&s.param, SCAN_TYPE_F32, &v, sizeof(v));
        scanner_first_scan(&s);
        check(find_value_at(&s.results, speed_addr, &v, sizeof(v)), "f32 first scan finds target_speed at 1.5");
        scanner_session_destroy(&s);
    }

    printf("--- T5: u32 and i64 spot checks ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_U32, SCAN_MODE_EXACT);
        unsigned int v = 4294967295u;
        scanner_value_set(&s.param, SCAN_TYPE_U32, &v, sizeof(v));
        scanner_first_scan(&s);
        check(find_addr(&s.results, u32_addr), "u32 first scan finds target_counter_u32");
        scanner_session_destroy(&s);

        scanner_session_init(&s, &target, SCAN_TYPE_I64, SCAN_MODE_EXACT);
        long long v64 = 0x123456789ABCll;
        scanner_value_set(&s.param, SCAN_TYPE_I64, &v64, sizeof(v64));
        scanner_first_scan(&s);
        check(find_addr(&s.results, i64_addr), "i64 first scan finds target_counter_i64");
        scanner_session_destroy(&s);
    }

    printf("--- T6: ASCII string scan ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_STRING, SCAN_MODE_EXACT);
        const char *text = "MemForgeASCII";
        scanner_value_set(&s.param, SCAN_TYPE_STRING, text, strlen(text));
        scanner_first_scan(&s);
        check(find_addr(&s.results, ascii_addr), "ASCII string scan finds target_ascii_string");
        scanner_session_destroy(&s);
    }

    printf("--- T7: UTF-16 string scan + AOB with wildcards ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_STRING, SCAN_MODE_EXACT);
        unsigned char u16[20] = {
            0x54,0x00, 0x65,0x00, 0x73,0x00, 0x74,0x00, 0x54,0x00,
            0x61,0x00, 0x72,0x00, 0x67,0x00, 0x65,0x00, 0x74,0x00,
        };
        scanner_value_set(&s.param, SCAN_TYPE_STRING, u16, sizeof(u16));
        scanner_first_scan(&s);
        check(find_addr(&s.results, name_addr), "UTF-16 string scan finds target_name");
        scanner_session_destroy(&s);

        /* AOB: 'T','e' (4 bytes), then 4 wildcard bytes (2 '??' wide chars),
           then 'T','t' -- should match exactly the start of target_name. */
        scanner_session_init(&s, &target, SCAN_TYPE_AOB, SCAN_MODE_EXACT);
        unsigned char pat[10]  = { 0x54,0x00, 0,0, 0,0, 0x74,0x00, 0x54,0x00 };
        unsigned char wild[10] = { 0,0,      1,1, 1,1, 0,0,      0,0 };
        scanner_value_set(&s.param, SCAN_TYPE_AOB, pat, sizeof(pat));
        scanner_value_set_wildcard(&s.param, wild, sizeof(wild));
        scanner_first_scan(&s);
        check(find_addr(&s.results, name_addr), "AOB with 4 wildcard bytes finds target_name");
        scanner_session_destroy(&s);
    }

    printf("--- T8: bad-mode first scan fails loud (does not narrow-mode seed a set) ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_I32, SCAN_MODE_CHANGED);
        check(scanner_first_scan(&s) != PLATFORM_OK, "first scan rejects CHANGED mode");
        check(s.has_results == 0 && s.results.count == 0, "failed first scan leaves no result set");
        scanner_session_destroy(&s);
    }

    process_detach(&target);

    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(out_r);
    CloseHandle(in_w);

    printf("\n%d failure(s)\n", failures);
    return failures > 0 ? 1 : 0;
}