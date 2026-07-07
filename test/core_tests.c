#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "core/process/process.h"
#include "core/memory/memory.h"
#include "core/scanner/scanner.h"

static int failures = 0;

static void check(int cond, const char *msg)
{
    if (!cond) {
        failures++;
        fprintf(stderr, "  FAIL: %s\n", msg);
    } else {
        printf("  ok: %s\n", msg);
    }
}

static void test_error_strings(void)
{
    printf("--- error string mapping ---\n");
    check(strcmp(process_error_string(PLATFORM_ERR_ACCESS_DENIED), "access denied (try running as administrator)") == 0,
          "PLATFORM_ERR_ACCESS_DENIED resolves");
    check(strcmp(process_error_string(PLATFORM_ERR_NOT_FOUND), "process not found") == 0,
          "PLATFORM_ERR_NOT_FOUND resolves");
    check(strcmp(process_error_string(PLATFORM_ERR_PARTIAL_READ), "partial read from target memory") == 0,
          "PLATFORM_ERR_PARTIAL_READ resolves");
    check(strcmp(process_error_string(PLATFORM_ERR_INTERNAL), "internal error (out of memory)") == 0,
          "PLATFORM_ERR_INTERNAL resolves");
    check(strcmp(process_error_string(PLATFORM_OK), "no error") == 0,
          "PLATFORM_OK resolves to 'no error'");
    check(strcmp(process_error_string((PlatformError)999), "unknown error") == 0,
          "out-of-range code falls back to 'unknown error'");
}

static void test_memory_boundary(void)
{
    printf("--- memory boundary validation ---\n");
    Target empty_target = {0};
    unsigned char buf[4];

    check(memory_read(NULL, 0x1000, buf, sizeof(buf)) != PLATFORM_OK,
          "memory_read with NULL target fails");
    check(memory_read(&empty_target, 0x1000, buf, sizeof(buf)) != PLATFORM_OK,
          "memory_read with empty target fails");
    check(memory_read(&empty_target, 0x1000, NULL, sizeof(buf)) != PLATFORM_OK,
          "memory_read with NULL buffer fails");
    check(memory_read(&empty_target, 0x1000, buf, 0) != PLATFORM_OK,
          "memory_read with zero size fails");

    check(memory_write(NULL, 0x1000, buf, sizeof(buf)) != PLATFORM_OK,
          "memory_write with NULL target fails");
    check(memory_write(&empty_target, 0x1000, buf, sizeof(buf)) != PLATFORM_OK,
          "memory_write with empty target fails");
    check(memory_write(&empty_target, 0x1000, NULL, sizeof(buf)) != PLATFORM_OK,
          "memory_write with NULL buffer fails");

    MemoryRegion region = {0};
    check(memory_query(NULL, 0x1000, &region) != PLATFORM_OK,
          "memory_query with NULL target fails");
    check(memory_query(&empty_target, 0x1000, &region) != PLATFORM_OK,
          "memory_query with empty target fails");
    check(memory_query(&empty_target, 0x1000, NULL) != PLATFORM_OK,
          "memory_query with NULL region fails");
}

static void test_process_boundary(void)
{
    printf("--- process boundary validation ---\n");
    check(process_list(NULL, NULL) != PLATFORM_OK,
          "process_list with NULL args fails");
    check(process_attach(0, NULL) != PLATFORM_OK,
          "process_attach with NULL target fails");

    unsigned int count = 0;
    check(process_list(NULL, &count) != PLATFORM_OK,
          "process_list with NULL entries pointer fails");
}

static void test_scanner_boundary(void)
{
    printf("--- scanner boundary validation ---\n");
    ScanResults results;
    scan_results_init(&results);
    scan_results_clear(&results);
    check(results.count == 0, "scan_results_clear zeroes count");
    scan_results_free(&results);

    Target empty_target = {0};
    ScanRegion *regions = NULL;
    size_t region_count;

    check(scanner_enumerate_regions(NULL, &regions, &region_count) != PLATFORM_OK,
          "scanner_enumerate_regions with NULL target fails");
    check(scanner_enumerate_regions(&empty_target, &regions, &region_count) != PLATFORM_OK,
          "scanner_enumerate_regions with empty target fails");
    check(scanner_enumerate_regions(&empty_target, NULL, &region_count) != PLATFORM_OK,
          "scanner_enumerate_regions with NULL out-params fails");

    ScanSession session;
    scanner_session_init(&session, &empty_target, SCAN_TYPE_I32, SCAN_MODE_EXACT);
    check(scanner_first_scan(NULL) != PLATFORM_OK, "scanner_first_scan NULL session fails");
    check(scanner_first_scan(&session) != PLATFORM_OK, "scanner_first_scan with empty target fails");
    check(scanner_next_scan(&session) != PLATFORM_OK, "scanner_next_scan without prior first scan fails");
    scanner_session_destroy(&session);

    scan_results_init(NULL);  /* must not crash on NULL */
    scan_results_free(NULL);  /* must not crash on NULL */
    check(1, "scan_results NULL guards do not crash");
}

int main(void)
{
    test_error_strings();
    test_memory_boundary();
    test_process_boundary();
    test_scanner_boundary();

    printf("\n%d failure(s)\n", failures);
    return failures > 0 ? 1 : 0;
}
