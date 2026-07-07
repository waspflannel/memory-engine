#include <stdlib.h>
#include <string.h>
#include "core/scanner/scanner.h"

/* Win32 region/state flags we validate against. Core does not include windows.h
   (only platform/ does), so these constants are stated here as the values the
   platform layer passes through unchecked. A drift between here and the SDK
   would surface at runtime (we'd skip or include the wrong regions). */
#define MEM_COMMIT      0x00001000u
#define PAGE_NOACCESS   0x00000001u
#define PAGE_GUARD      0x00000100u

/* ---- Public API (order matches scanner.h) ---- */

void scan_results_init(ScanResults *results)
{
    if (!results) return;
    results->hits     = NULL;
    results->count    = 0;
    results->capacity = 0;
}

void scan_results_free(ScanResults *results)
{
    if (!results) return;
    free(results->hits);
    results->hits     = NULL;
    results->count    = 0;
    results->capacity = 0;
}

void scan_results_clear(ScanResults *results)
{
    if (!results) return;
    results->count = 0;
}

PlatformError scanner_enumerate_regions(const Target *target, ScanRegion **regions, size_t *count)
{
    if (!target || !target->handle || !regions || !count) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    *regions = NULL;
    *count   = 0;

    size_t cap = 64;
    size_t n = 0;
    ScanRegion *list = (ScanRegion *)malloc(cap * sizeof(ScanRegion));
    if (!list) {
        return PLATFORM_ERR_INTERNAL;
    }

    unsigned long long address = 0;
    for (;;) {
        MemoryRegion info = {0};
        PlatformError err = memory_query(target, address, &info);
        if (err != PLATFORM_OK) {
            /* VirtualQueryEx only fails past the end of user address space; stop. */
            break;
        }

        int committed = (info.state == MEM_COMMIT);
        int accessible = (info.protect != PAGE_NOACCESS) && !(info.protect & PAGE_GUARD);
        if (committed && accessible) {
            if (n >= cap) {
                size_t new_cap = cap * 2;
                ScanRegion *grown = (ScanRegion *)realloc(list, new_cap * sizeof(ScanRegion));
                if (!grown) {
                    free(list);
                    return PLATFORM_ERR_INTERNAL;
                }
                list = grown;
                cap  = new_cap;
            }
            list[n].base = info.base;
            list[n].size = info.size;
            n++;
        }

        unsigned long long next = info.base + info.size;
        if (next <= address) {
            /* No forward progress (zero-size region or wrapped) — stop, don't spin. */
            break;
        }
        address = next;
    }

    if (n == 0) {
        free(list);
        return PLATFORM_OK;
    }

    *regions = list;
    *count   = n;
    return PLATFORM_OK;
}

void scanner_free_regions(ScanRegion *regions)
{
    free(regions);
}