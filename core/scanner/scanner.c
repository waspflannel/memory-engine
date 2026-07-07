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

/* First-scan read chunk. The buffer and the count passed to memory_read stay
   paired through this constant. */
#define SCAN_CHUNK_BYTES 65536

/* Forward declarations — definitions at bottom of file. */
static int scan_results_append(ScanResults *results, unsigned long long address, const unsigned char *value, size_t width);

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

void scanner_session_init(ScanSession *session, const Target *target, ScanType type, ScanMode mode)
{
    if (!session) return;
    session->target      = target;
    session->type         = type;
    session->mode         = mode;
    session->value_i32    = 0;
    scan_results_init(&session->results);
    session->has_results  = 0;
}

void scanner_session_destroy(ScanSession *session)
{
    if (!session) return;
    scan_results_free(&session->results);
    session->target = NULL;
}

PlatformError scanner_first_scan(ScanSession *session)
{
    if (!session || !session->target || !session->target->handle) {
        return PLATFORM_ERR_INVALID_PARAM;
    }
    /* Only the i32/exact slice is implemented yet (phase-2 build order). */
    if (session->type != SCAN_TYPE_I32 || session->mode != SCAN_MODE_EXACT) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    scan_results_clear(&session->results);

    ScanRegion *regions = NULL;
    size_t region_count = 0;
    PlatformError err = scanner_enumerate_regions(session->target, &regions, &region_count);
    if (err != PLATFORM_OK) {
        return err;
    }

    const unsigned int W = 4;
    unsigned char want[4];
    int value = session->value_i32;
    want[0] = (unsigned char)(value & 0xFF);
    want[1] = (unsigned char)((value >> 8) & 0xFF);
    want[2] = (unsigned char)((value >> 16) & 0xFF);
    want[3] = (unsigned char)((value >> 24) & 0xFF);

    unsigned char buf[SCAN_CHUNK_BYTES];
    for (size_t r = 0; r < region_count; r++) {
        unsigned long long addr = regions[r].base;
        size_t remaining = regions[r].size;

        while (remaining >= W) {
            size_t take = remaining < SCAN_CHUNK_BYTES ? remaining : SCAN_CHUNK_BYTES;
            PlatformError rd = memory_read(session->target, addr, buf, take);
            if (rd != PLATFORM_OK) {
                /* Per-region failure: skip the rest of this region, keep scanning
                   the others. Never paper over with zeros. */
                break;
            }

            size_t last = take - W;
            for (size_t off = 0; off <= last; off++) {
                /* Short-circuit on the first byte before the full 4-byte compare. */
                if (buf[off] == want[0] &&
                    buf[off + 1] == want[1] &&
                    buf[off + 2] == want[2] &&
                    buf[off + 3] == want[3]) {
                    if (!scan_results_append(&session->results, addr + off, buf + off, W)) {
                        scanner_free_regions(regions);
                        return PLATFORM_ERR_INTERNAL;
                    }
                }
            }

            size_t advance = take - W + 1;
            addr      += advance;
            remaining -= advance;
        }
    }

    scanner_free_regions(regions);
    session->has_results = 1;
    return PLATFORM_OK;
}

PlatformError scanner_next_scan(ScanSession *session)
{
    if (!session || !session->target || !session->target->handle) {
        return PLATFORM_ERR_INVALID_PARAM;
    }
    if (!session->has_results) {
        return PLATFORM_ERR_INVALID_PARAM;
    }
    if (session->type != SCAN_TYPE_I32 || session->mode != SCAN_MODE_EXACT) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    const unsigned int W = 4;
    unsigned char want[4];
    int value = session->value_i32;
    want[0] = (unsigned char)(value & 0xFF);
    want[1] = (unsigned char)((value >> 8) & 0xFF);
    want[2] = (unsigned char)((value >> 16) & 0xFF);
    want[3] = (unsigned char)((value >> 24) & 0xFF);

    ScanHit *hits = session->results.hits;
    size_t survivors = 0;
    for (size_t i = 0; i < session->results.count; i++) {
        unsigned char cur[4];
        PlatformError rd = memory_read(session->target, hits[i].address, cur, W);
        if (rd != PLATFORM_OK) {
            /* Target dropped this page since the first scan; drop the hit, don't fake. */
            continue;
        }
        if (cur[0] == want[0] && cur[1] == want[1] && cur[2] == want[2] && cur[3] == want[3]) {
            /* In-place compact: survivors <= i, so reads of hits[i] stay safe. */
            hits[survivors].address = hits[i].address;
            memcpy(hits[survivors].value, cur, W);
            survivors++;
        }
    }
    session->results.count = survivors;
    return PLATFORM_OK;
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

/* ---- Static helpers ---- */

static int scan_results_append(ScanResults *results, unsigned long long address, const unsigned char *value, size_t width)
{
    if (results->count >= results->capacity) {
        size_t new_cap = results->capacity ? results->capacity * 2 : 64;
        ScanHit *grown = (ScanHit *)realloc(results->hits, new_cap * sizeof(ScanHit));
        if (!grown) {
            return 0;
        }
        results->hits     = grown;
        results->capacity = new_cap;
    }
    results->hits[results->count].address = address;
    if (width > SCAN_VALUE_MAX) width = SCAN_VALUE_MAX;
    memcpy(results->hits[results->count].value, value, width);
    results->count++;
    return 1;
}