#include <stdlib.h>
#include <stdint.h>
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
static int value_equals(const unsigned char *cur, const ScanValue *p);
static int numeric_compare(ScanType type, const unsigned char *a, const unsigned char *b);
static void numeric_add(ScanType type, const unsigned char *a, const unsigned char *b, int sign, unsigned char *out);
static int keep_hit(const ScanSession *session, const unsigned char *current, const unsigned char *prev, size_t width);

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

unsigned short scan_type_width(ScanType type)
{
    switch (type) {
    case SCAN_TYPE_I8:
    case SCAN_TYPE_U8:        return 1;
    case SCAN_TYPE_I16:
    case SCAN_TYPE_U16:       return 2;
    case SCAN_TYPE_I32:
    case SCAN_TYPE_U32:
    case SCAN_TYPE_F32:       return 4;
    case SCAN_TYPE_I64:
    case SCAN_TYPE_U64:
    case SCAN_TYPE_F64:       return 8;
    default:                  return 0;   /* SCAN_TYPE_STRING / SCAN_TYPE_AOB: variable */
    }
}

void scanner_value_set(ScanValue *value, ScanType type, const void *bytes, size_t len)
{
    if (!value) return;
    value->type = type;
    unsigned short w = scan_type_width(type);
    value->width = w ? w : (unsigned short)(len > SCAN_VALUE_MAX ? SCAN_VALUE_MAX : len);
    if (bytes && value->width) {
        memcpy(value->bytes, bytes, value->width);
    }
    memset(value->wild, 0, sizeof(value->wild));
}

void scanner_value_set_wildcard(ScanValue *value, const unsigned char *wild, size_t len)
{
    if (!value || !wild) return;
    size_t n = len > SCAN_VALUE_MAX ? SCAN_VALUE_MAX : len;
    memcpy(value->wild, wild, n);
}

void scanner_session_init(ScanSession *session, const Target *target, ScanType type, ScanMode mode)
{
    if (!session) return;
    session->target = target;
    session->mode   = mode;
    scanner_value_set(&session->param, type, NULL, 0);
    scanner_value_set(&session->param2, type, NULL, 0);
    scan_results_init(&session->results);
    session->has_results = 0;
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

    ScanMode m = session->mode;
    if (m != SCAN_MODE_EXACT && m != SCAN_MODE_UNKNOWN_INITIAL) {
        /* Only exact and unknown-initial seed a result set; the other modes narrow. */
        return PLATFORM_ERR_INVALID_PARAM;
    }

    unsigned short width = session->param.width;
    if (m == SCAN_MODE_EXACT && width == 0) {
        return PLATFORM_ERR_INVALID_PARAM;   /* no value set */
    }
    if (m == SCAN_MODE_UNKNOWN_INITIAL) {
        width = scan_type_width(session->param.type);
        if (width == 0) {
            return PLATFORM_ERR_INVALID_PARAM;  /* unknown-initial needs a fixed-width numeric type */
        }
    }

    scan_results_clear(&session->results);

    ScanRegion *regions = NULL;
    size_t region_count = 0;
    PlatformError err = scanner_enumerate_regions(session->target, &regions, &region_count);
    if (err != PLATFORM_OK) {
        return err;
    }

    const size_t W = width;
    const ScanValue *want = &session->param;
    int snapshot = (m == SCAN_MODE_UNKNOWN_INITIAL);

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
                if (!snapshot && !value_equals(buf + off, want)) {
                    continue;
                }
                if (!scan_results_append(&session->results, addr + off, buf + off, W)) {
                    scanner_free_regions(regions);
                    return PLATFORM_ERR_INTERNAL;
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
    ScanMode m = session->mode;
    if (m == SCAN_MODE_UNKNOWN_INITIAL) {
        return PLATFORM_ERR_INVALID_PARAM;  /* first-scan-only mode; pick a narrowing mode */
    }
    if (session->param.width == 0) {
        /* Width is the byte size of the value we read and compare. Established by
           the first scan; zero means it never ran (or no value for absolute modes). */
        return PLATFORM_ERR_INVALID_PARAM;
    }

    const size_t W = session->param.width;

    ScanHit *hits = session->results.hits;
    size_t survivors = 0;
    unsigned char cur[SCAN_VALUE_MAX];
    for (size_t i = 0; i < session->results.count; i++) {
        PlatformError rd = memory_read(session->target, hits[i].address, cur, W);
        if (rd != PLATFORM_OK) {
            /* Target dropped this page since the last scan; drop the hit, don't fake. */
            continue;
        }
        if (keep_hit(session, cur, hits[i].value, W)) {
            /* In-place compact: survivors <= i, so reads of hits[i] stay safe.
               Store the freshly-read value so the next relative-mode pass sees it. */
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

static int type_is_numeric(ScanType type)
{
    return type == SCAN_TYPE_I8 || type == SCAN_TYPE_I16 ||
           type == SCAN_TYPE_I32 || type == SCAN_TYPE_I64 ||
           type == SCAN_TYPE_U8 || type == SCAN_TYPE_U16 ||
           type == SCAN_TYPE_U32 || type == SCAN_TYPE_U64 ||
           type == SCAN_TYPE_F32 || type == SCAN_TYPE_F64;
}

static int value_equals(const unsigned char *cur, const ScanValue *p)
{
    /* Fast-path the common case: a literal first byte rejects the vast majority
       of offsets before we ever look at the rest. `??` (mask=1) skips the byte. */
    if (!p->wild[0] && cur[0] != p->bytes[0]) {
        return 0;
    }
    for (unsigned short i = 0; i < p->width; i++) {
        if (!p->wild[i] && cur[i] != p->bytes[i]) {
            return 0;
        }
    }
    return 1;
}

/*
 * Compare two raw-le byte buffers as the numeric type `type`. Returns -1 / 0 / 1
 * for a < b / == / a > b. For floats we return -2 on NaN so callers can drop
 * the hit (NaN fails every inc/dec/between test). String/AOB are non-numeric,
 * returned as -2 too -- the modes that call this guard against them at the TUI
 * boundary (only changed/unchanged/exact apply to AOB/string).
 */
static int numeric_compare(ScanType type, const unsigned char *a, const unsigned char *b)
{
    switch (type) {
    case SCAN_TYPE_I8: {
        int8_t x = (int8_t)a[0],  y = (int8_t)b[0];
        return (x > y) - (x < y);
    }
    case SCAN_TYPE_U8: {
        uint8_t x = a[0], y = b[0];
        return (x > y) - (x < y);
    }
    case SCAN_TYPE_I16: { int16_t x, y; memcpy(&x, a, 2); memcpy(&y, b, 2); return (x > y) - (x < y); }
    case SCAN_TYPE_U16: { uint16_t x, y; memcpy(&x, a, 2); memcpy(&y, b, 2); return (x > y) - (x < y); }
    case SCAN_TYPE_I32: { int32_t x, y; memcpy(&x, a, 4); memcpy(&y, b, 4); return (x > y) - (x < y); }
    case SCAN_TYPE_U32: { uint32_t x, y; memcpy(&x, a, 4); memcpy(&y, b, 4); return (x > y) - (x < y); }
    case SCAN_TYPE_I64: { int64_t x, y; memcpy(&x, a, 8); memcpy(&y, b, 8); return (x > y) - (x < y); }
    case SCAN_TYPE_U64: { uint64_t x, y; memcpy(&x, a, 8); memcpy(&y, b, 8); return (x > y) - (x < y); }
    case SCAN_TYPE_F32: {
        float x, y; memcpy(&x, a, 4); memcpy(&y, b, 4);
        if (x != x || y != y) return -2;
        return (x > y) - (x < y);
    }
    case SCAN_TYPE_F64: {
        double x, y; memcpy(&x, a, 8); memcpy(&y, b, 8);
        if (x != x || y != y) return -2;
        return (x > y) - (x < y);
    }
    default:
        return -2;  /* string/AOB: not numeric */
    }
}

/* out = a +/- b interpreted as the numeric type. noop for non-numeric types. */
static void numeric_add(ScanType type, const unsigned char *a, const unsigned char *b,
                        int sign, unsigned char *out)
{
    switch (type) {
    case SCAN_TYPE_I8: { int8_t x, y; memcpy(&x, a, 1); memcpy(&y, b, 1); int8_t r = sign > 0 ? (int8_t)(x + y) : (int8_t)(x - y); memcpy(out, &r, 1); break; }
    case SCAN_TYPE_U8: { uint8_t x, y; memcpy(&x, a, 1); memcpy(&y, b, 1); uint8_t r = sign > 0 ? (uint8_t)(x + y) : (uint8_t)(x - y); memcpy(out, &r, 1); break; }
    case SCAN_TYPE_I16: { int16_t x, y; memcpy(&x, a, 2); memcpy(&y, b, 2); int16_t r = sign > 0 ? (int16_t)(x + y) : (int16_t)(x - y); memcpy(out, &r, 2); break; }
    case SCAN_TYPE_U16: { uint16_t x, y; memcpy(&x, a, 2); memcpy(&y, b, 2); uint16_t r = sign > 0 ? (uint16_t)(x + y) : (uint16_t)(x - y); memcpy(out, &r, 2); break; }
    case SCAN_TYPE_I32: { int32_t x, y; memcpy(&x, a, 4); memcpy(&y, b, 4); int32_t r = sign > 0 ? (x + y) : (x - y); memcpy(out, &r, 4); break; }
    case SCAN_TYPE_U32: { uint32_t x, y; memcpy(&x, a, 4); memcpy(&y, b, 4); uint32_t r = sign > 0 ? (x + y) : (x - y); memcpy(out, &r, 4); break; }
    case SCAN_TYPE_I64: { int64_t x, y; memcpy(&x, a, 8); memcpy(&y, b, 8); int64_t r = sign > 0 ? (x + y) : (x - y); memcpy(out, &r, 8); break; }
    case SCAN_TYPE_U64: { uint64_t x, y; memcpy(&x, a, 8); memcpy(&y, b, 8); uint64_t r = sign > 0 ? (x + y) : (x - y); memcpy(out, &r, 8); break; }
    case SCAN_TYPE_F32: { float x, y; memcpy(&x, a, 4); memcpy(&y, b, 4); float r = sign > 0 ? (x + y) : (x - y); memcpy(out, &r, 4); break; }
    case SCAN_TYPE_F64: { double x, y; memcpy(&x, a, 8); memcpy(&y, b, 8); double r = sign > 0 ? (x + y) : (x - y); memcpy(out, &r, 8); break; }
    default: break;
    }
}

/* Apply the current scan-mode predicate to a freshly-read value vs the last-seen
   value. Width ties the two buffers together (always param.width for the mode). */
static int keep_hit(const ScanSession *session, const unsigned char *current,
                    const unsigned char *prev, size_t width)
{
    ScanType type = session->param.type;
    switch (session->mode) {
    case SCAN_MODE_EXACT:        return value_equals(current, &session->param);
    case SCAN_MODE_CHANGED:      return memcmp(current, prev, width) != 0;
    case SCAN_MODE_UNCHANGED:    return memcmp(current, prev, width) == 0;
    case SCAN_MODE_INCREASED:    return numeric_compare(type, current, prev) > 0;
    case SCAN_MODE_DECREASED:    return numeric_compare(type, current, prev) < 0;
    case SCAN_MODE_INCREASED_BY: {
        if (!type_is_numeric(type)) return 0;
        unsigned char tmp[SCAN_VALUE_MAX];
        numeric_add(type, prev, session->param.bytes, +1, tmp);
        return memcmp(current, tmp, width) == 0;
    }
    case SCAN_MODE_DECREASED_BY: {
        if (!type_is_numeric(type)) return 0;
        unsigned char tmp[SCAN_VALUE_MAX];
        numeric_add(type, prev, session->param.bytes, -1, tmp);
        return memcmp(current, tmp, width) == 0;
    }
    case SCAN_MODE_BETWEEN: {
        int lo = numeric_compare(type, current, session->param.bytes);
        int hi = numeric_compare(type, current, session->param2.bytes);
        return lo >= 0 && lo != -2 && hi <= 0 && hi != -2;
    }
    case SCAN_MODE_UNKNOWN_INITIAL:
        return 0;  /* first-scan-only mode; never a narrowing predicate */
    }
    return 0;
}

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