#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "core/process/process.h"
#include "core/memory/memory.h"

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
    check(strcmp(proc_error_string(PLAT_ERR_ACCESS_DENIED), "access denied (try running as administrator)") == 0,
          "PLAT_ERR_ACCESS_DENIED resolves");
    check(strcmp(proc_error_string(PLAT_ERR_NOT_FOUND), "process not found") == 0,
          "PLAT_ERR_NOT_FOUND resolves");
    check(strcmp(proc_error_string(PLAT_ERR_PARTIAL_READ), "partial read from target memory") == 0,
          "PLAT_ERR_PARTIAL_READ resolves");
    check(strcmp(proc_error_string(PLAT_ERR_INTERNAL), "internal error (out of memory)") == 0,
          "PLAT_ERR_INTERNAL resolves");
    check(strcmp(proc_error_string(PLAT_OK), "no error") == 0,
          "PLAT_OK resolves to 'no error'");
    check(strcmp(proc_error_string((PlatError)999), "unknown error") == 0,
          "out-of-range code falls back to 'unknown error'");
}

static void test_mem_boundary(void)
{
    printf("--- memory boundary validation ---\n");
    Target empty_target = {0};
    unsigned char buf[4];

    check(mem_read(NULL, 0x1000, buf, sizeof(buf)) != PLAT_OK,
          "mem_read with NULL target fails");
    check(mem_read(&empty_target, 0x1000, buf, sizeof(buf)) != PLAT_OK,
          "mem_read with empty target fails");
    check(mem_read(&empty_target, 0x1000, NULL, sizeof(buf)) != PLAT_OK,
          "mem_read with NULL buffer fails");
    check(mem_read(&empty_target, 0x1000, buf, 0) != PLAT_OK,
          "mem_read with zero size fails");

    check(mem_write(NULL, 0x1000, buf, sizeof(buf)) != PLAT_OK,
          "mem_write with NULL target fails");
    check(mem_write(&empty_target, 0x1000, buf, sizeof(buf)) != PLAT_OK,
          "mem_write with empty target fails");
    check(mem_write(&empty_target, 0x1000, NULL, sizeof(buf)) != PLAT_OK,
          "mem_write with NULL buffer fails");

    MemRegion region = {0};
    check(mem_query(NULL, 0x1000, &region) != PLAT_OK,
          "mem_query with NULL target fails");
    check(mem_query(&empty_target, 0x1000, &region) != PLAT_OK,
          "mem_query with empty target fails");
    check(mem_query(&empty_target, 0x1000, NULL) != PLAT_OK,
          "mem_query with NULL region fails");
}

static void test_proc_boundary(void)
{
    printf("--- process boundary validation ---\n");
    check(proc_enumerate(NULL, NULL) != PLAT_OK,
          "proc_enumerate with NULL args fails");
    check(proc_attach(0, NULL) != PLAT_OK,
          "proc_attach with NULL target fails");

    unsigned int count = 0;
    check(proc_enumerate(NULL, &count) != PLAT_OK,
          "proc_enumerate with NULL entries pointer fails");
}

int main(void)
{
    test_error_strings();
    test_mem_boundary();
    test_proc_boundary();

    printf("\n%d failure(s)\n", failures);
    return failures > 0 ? 1 : 0;
}
