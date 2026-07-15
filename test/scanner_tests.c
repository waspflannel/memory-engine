#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "core/process/process.h"
#include "core/scanner/scanner.h"
#include "core/memory/memory.h"

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

static void check_fixed_type(Target *target, ScanType type, const void *value,
                             size_t width, const char *message)
{
    ScanSession session;
    scanner_session_init(&session, target, type);
    ScanResults results;
    results_init(&results);
    ScanRegion region = { (unsigned long long)(UINT_PTR)value, width };
    int ok = scanner_value_set(&session.param, type, value, width) == PLATFORM_OK &&
             scanner_find_hits(&session, &region, 1, &results) == PLATFORM_OK &&
             results.count == 1 && results.addresses[0] == region.base;
    check(ok, message);
    results_free(&results);
    scanner_session_destroy(&session);
}

int main(void)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE out_r, out_w, in_r, in_w;
    if (!CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&in_r, &in_w, &sa, 0)) {
        printf("FAIL: CreatePipe\n");
        return 1;
    }
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(in_w,  HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    si.hStdInput = in_r;
    PROCESS_INFORMATION pi = {0};

    WCHAR cmd[] = L"test_target.exe";
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("FAIL: cannot spawn test_target.exe (it must sit beside scanner_tests.exe)\n");
        CloseHandle(out_r); CloseHandle(out_w); CloseHandle(in_r); CloseHandle(in_w);
        return 1;
    }
    CloseHandle(out_w);
    CloseHandle(in_r);

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
        scanner_session_init(&s, &target, SCAN_TYPE_I32);
        int v = 100;
        scanner_value_set(&s.param, SCAN_TYPE_I32, &v, sizeof(v));

        ScanRegion *regs = NULL;
        size_t nregs = 0;
        check(scanner_list_regions(&target, &regs, &nregs) == PLATFORM_OK, "list_regions ok");

        ScanResults single; results_init(&single);
        check(scanner_find_hits(&s, regs, nregs, &single) == PLATFORM_OK, "scanner_find_hits (single) ok");

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
        results_free(&single);
        scanner_session_destroy(&s);
    }

    printf("--- T2: exact narrowing after a value change ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_I32);
        int v100 = 100;
        scanner_value_set(&s.param, SCAN_TYPE_I32, &v100, sizeof(v100));
        check(scanner_first_scan(&s) == PLATFORM_OK, "first scan for 100");

        size_t prior_count = s.results.count;
        unsigned long long *prior_addresses = s.results.addresses;
        float wrong_type = 100.0f;
        scanner_value_set(&s.param, SCAN_TYPE_F32, &wrong_type, sizeof(wrong_type));
        check(scanner_next_scan(&s) == PLATFORM_ERR_INVALID_PARAM,
              "next scan rejects a same-width type change");
        check(s.results.count == prior_count && s.results.addresses == prior_addresses,
              "rejected type change preserves prior results atomically");

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

    printf("--- T3: first scan requires an explicit value ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_I32);
        check(scanner_first_scan(&s) != PLATFORM_OK, "first scan rejects an unset value");
        check(s.has_results == 0 && s.results.count == 0, "failed first scan leaves no result set");
        scanner_session_destroy(&s);
    }

    printf("--- T4: f32 spot check ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_F32);
        float v = 1.5f;
        scanner_value_set(&s.param, SCAN_TYPE_F32, &v, sizeof(v));
        scanner_first_scan(&s);
        check(find_value_at(&s.results, speed_addr, &v, sizeof(v)), "f32 first scan finds target_speed at 1.5");
        scanner_session_destroy(&s);
    }

    printf("--- T5: u32 and i64 spot checks ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_U32);
        unsigned int v = 4294967295u;
        scanner_value_set(&s.param, SCAN_TYPE_U32, &v, sizeof(v));
        scanner_first_scan(&s);
        check(find_addr(&s.results, u32_addr), "u32 first scan finds target_counter_u32");
        scanner_session_destroy(&s);

        scanner_session_init(&s, &target, SCAN_TYPE_I64);
        long long v64 = 0x123456789ABCll;
        scanner_value_set(&s.param, SCAN_TYPE_I64, &v64, sizeof(v64));
        scanner_first_scan(&s);
        check(find_addr(&s.results, i64_addr), "i64 first scan finds target_counter_i64");
        scanner_session_destroy(&s);
    }

    printf("--- T6: ASCII string scan ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_STRING);
        const char *text = "MemForgeASCII";
        scanner_value_set(&s.param, SCAN_TYPE_STRING, text, strlen(text));
        scanner_first_scan(&s);
        check(find_addr(&s.results, ascii_addr), "ASCII string scan finds target_ascii_string");
        scanner_session_destroy(&s);
    }

    printf("--- T7: UTF-16 string scan + exact AOB ---\n");
    {
        ScanSession s;
        scanner_session_init(&s, &target, SCAN_TYPE_STRING);
        unsigned char u16[20] = {
            0x54,0x00, 0x65,0x00, 0x73,0x00, 0x74,0x00, 0x54,0x00,
            0x61,0x00, 0x72,0x00, 0x67,0x00, 0x65,0x00, 0x74,0x00,
        };
        scanner_value_set(&s.param, SCAN_TYPE_STRING, u16, sizeof(u16));
        scanner_first_scan(&s);
        check(find_addr(&s.results, name_addr), "UTF-16 string scan finds target_name");
        scanner_session_destroy(&s);

        scanner_session_init(&s, &target, SCAN_TYPE_AOB);
        scanner_value_set(&s.param, SCAN_TYPE_AOB, u16, sizeof(u16));
        scanner_first_scan(&s);
        check(find_addr(&s.results, name_addr), "exact AOB scan finds target_name");
        scanner_session_destroy(&s);
    }

    printf("--- T8: every fixed-width type and chunk overlap ---\n");
    {
        Target self = {0};
        self.handle = GetCurrentProcess();
        int8_t i8 = -12;
        int16_t i16 = -1234;
        uint8_t u8 = 250;
        uint16_t u16 = 65000;
        uint64_t u64 = UINT64_C(0xFEDCBA9876543210);
        double f64 = 123.25;
        check_fixed_type(&self, SCAN_TYPE_I8, &i8, sizeof(i8), "i8 controlled scan");
        check_fixed_type(&self, SCAN_TYPE_I16, &i16, sizeof(i16), "i16 controlled scan");
        check_fixed_type(&self, SCAN_TYPE_U8, &u8, sizeof(u8), "u8 controlled scan");
        check_fixed_type(&self, SCAN_TYPE_U16, &u16, sizeof(u16), "u16 controlled scan");
        check_fixed_type(&self, SCAN_TYPE_U64, &u64, sizeof(u64), "u64 controlled scan");
        check_fixed_type(&self, SCAN_TYPE_F64, &f64, sizeof(f64), "f64 controlled scan");

        unsigned char *memory = (unsigned char *)VirtualAlloc(NULL, 65544,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        check(memory != NULL, "allocate controlled chunk-boundary region");
        if (memory) {
            memset(memory, 0, 65544);
            const unsigned char pattern[] = { 0xDE, 0xAD, 0xBE, 0xEF };
            memcpy(memory + 65534, pattern, sizeof(pattern));
            ScanSession session;
            scanner_session_init(&session, &self, SCAN_TYPE_AOB);
            scanner_value_set(&session.param, SCAN_TYPE_AOB, pattern, sizeof(pattern));
            ScanRegion region = { (unsigned long long)(UINT_PTR)memory, 65544 };
            ScanResults results;
            results_init(&results);
            check(scanner_find_hits(&session, &region, 1, &results) == PLATFORM_OK,
                  "chunk-boundary controlled scan succeeds");
            check(find_addr(&results, region.base + 65534),
                  "match spanning 64 KiB chunk boundary is found");
            results_free(&results);
            scanner_session_destroy(&session);
            VirtualFree(memory, 0, MEM_RELEASE);
        }

        SYSTEM_INFO system_info = {0};
        GetSystemInfo(&system_info);
        size_t page_size = system_info.dwPageSize;
        unsigned char *split_memory = (unsigned char *)VirtualAlloc(NULL, page_size * 2,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        check(split_memory != NULL, "allocate controlled split-protection region");
        if (split_memory) {
            const unsigned char pattern[] = { 0xFA, 0xCE, 0xCA, 0xFE };
            memset(split_memory, 0, page_size * 2);
            memcpy(split_memory + page_size - 2, pattern, sizeof(pattern));

            DWORD old_protect = 0;
            BOOL made_readonly = VirtualProtect(split_memory + page_size, page_size,
                                                PAGE_READONLY, &old_protect);
            check(made_readonly != 0, "split adjacent pages into readable protections");
            if (made_readonly) {
                ScanSession session;
                scanner_session_init(&session, &self, SCAN_TYPE_AOB);
                scanner_value_set(&session.param, SCAN_TYPE_AOB, pattern, sizeof(pattern));
                ScanRegion region = {
                    (unsigned long long)(UINT_PTR)split_memory,
                    page_size * 2,
                };
                ScanResults results;
                results_init(&results);
                check(scanner_find_hits(&session, &region, 1, &results) == PLATFORM_OK,
                      "scan crosses adjacent readable protection regions");
                check(find_addr(&results, region.base + page_size - 2),
                      "match spanning a readable protection boundary is found");
                check(results.skipped_regions == 0,
                      "readable protection boundary is not reported as skipped");
                results_free(&results);

                DWORD readonly_protect = 0;
                BOOL made_inaccessible = VirtualProtect(split_memory + page_size, page_size,
                                                        PAGE_NOACCESS, &readonly_protect);
                check(made_inaccessible != 0, "make an enumerated page inaccessible");
                if (made_inaccessible) {
                    results_init(&results);
                    check(scanner_find_hits(&session, &region, 1, &results) == PLATFORM_OK,
                          "live inaccessible region does not abort first-scan matching");
                    check(results.skipped_regions == 1,
                          "live inaccessible region is counted as skipped");
                    results_free(&results);
                }
                scanner_session_destroy(&session);
            }
            VirtualFree(split_memory, 0, MEM_RELEASE);
        }

        int *candidate = (int *)VirtualAlloc(NULL, page_size * 2,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        check(candidate != NULL, "allocate controlled next-scan candidates");
        if (candidate) {
            memset(candidate, 0, page_size * 2);
            int *surviving_candidate = (int *)((unsigned char *)candidate + page_size);
            *candidate = 0x13579BDF;
            *surviving_candidate = *candidate;
            ScanSession session;
            scanner_session_init(&session, &self, SCAN_TYPE_I32);
            scanner_value_set(&session.param, SCAN_TYPE_I32, candidate, sizeof(*candidate));
            ScanRegion region = {
                (unsigned long long)(UINT_PTR)candidate,
                page_size * 2,
            };
            check(scanner_find_hits(&session, &region, 1, &session.results) == PLATFORM_OK &&
                  session.results.count == 2,
                  "create two controlled next-scan hits");
            session.results_type = SCAN_TYPE_I32;
            session.has_results = 1;

            DWORD old_protect = 0;
            BOOL made_inaccessible = VirtualProtect(candidate, page_size, PAGE_NOACCESS, &old_protect);
            check(made_inaccessible != 0, "make a next-scan candidate inaccessible");
            if (made_inaccessible) {
                check(scanner_next_scan(&session) == PLATFORM_OK,
                      "live unreadable candidate does not abort next scan");
                check(session.results.count == 1 && session.results.unreadable_candidates == 1,
                      "live unreadable candidate is removed and counted while scanning continues");
                check(session.results.count == 1 &&
                      session.results.addresses[0] == (unsigned long long)(UINT_PTR)surviving_candidate,
                      "readable candidate after an unreadable hit still survives");
                check(scanner_next_scan(&session) == PLATFORM_OK &&
                      session.results.count == 1 && session.results.unreadable_candidates == 0,
                      "next-scan unreadable count describes only the latest scan");
            }
            scanner_session_destroy(&session);
            VirtualFree(candidate, 0, MEM_RELEASE);
        }
    }

    printf("--- T9: target exit is loud and scan state stays atomic ---\n");
    {
        ScanSession session;
        scanner_session_init(&session, &target, SCAN_TYPE_I32);
        int value = 25;
        scanner_value_set(&session.param, SCAN_TYPE_I32, &value, sizeof(value));
        check(scanner_first_scan(&session) == PLATFORM_OK, "pre-exit first scan succeeds");
        size_t prior_count = session.results.count;
        unsigned long long *prior_addresses = session.results.addresses;

        check(TerminateProcess(pi.hProcess, 0) != 0, "terminate target for failure injection");
        WaitForSingleObject(pi.hProcess, 2000);
        int alive = 1;
        check(process_is_alive(&target, &alive) == PLATFORM_OK && !alive,
              "terminated target is reported dead");
        check(scanner_next_scan(&session) != PLATFORM_OK,
              "next scan reports target read failure");
        check(session.results.count == prior_count && session.results.addresses == prior_addresses,
              "failed next scan preserves prior result set");
        check(scanner_first_scan(&session) != PLATFORM_OK,
              "first scan reports target query failure");
        check(!session.has_results && session.results.count == 0 && !session.results.addresses,
              "failed first scan leaves no partial result set");
        scanner_session_destroy(&session);
    }

    process_detach(&target);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(out_r);
    CloseHandle(in_w);

    printf("\n%d failure(s)\n", failures);
    return failures > 0 ? 1 : 0;
}
