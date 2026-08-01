#ifndef TEST_H
#define TEST_H

#include <stdio.h>

static int failures;

static void check(int condition, const char *message)
{
    if (condition) {
        printf("  ok: %s\n", message);
    } else {
        fprintf(stderr, "  FAIL: %s\n", message);
        failures++;
    }
}

#endif
