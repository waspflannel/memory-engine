#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <threads.h>
#include "core/scanner/scanner.h"

/* Duplicated Win32 values; the platform layer passes these through raw. */
#define MEM_COMMIT      0x00001000u
#define PAGE_NOACCESS   0x00000001u
#define PAGE_GUARD      0x00000100u

#define SCAN_CHUNK_BYTES 65536

#define SCAN_MAX_THREADS 8

typedef struct ScanWork {
    const ScanSession *session;
    const ScanRegion  *regions;
    size_t             count;
    unsigned short     width;
    int                snapshot;
    ScanResults        results;
    PlatformError      err;
} ScanWork;

/* Forward declarations — definitions at bottom of file. */
static int  scan_results_append(ScanResults *results, unsigned long long address, const unsigned char *value, size_t width);
static int  value_equals(const unsigned char *cur, const ScanValue *p);
static int  numeric_compare(ScanType type, const unsigned char *a, const unsigned char *b);
static void numeric_add(ScanType type, const unsigned char *a, const unsigned char *b, int sign, unsigned char *out);
static int  keep_hit(const ScanSession *session, const unsigned char *current, const unsigned char *prev, size_t width);
static PlatformError scan_regions(const ScanSession *session, const ScanRegion *regions, size_t count,
                                   unsigned short width, int snapshot, ScanResults *out);
static int  scan_worker(void *arg);
static PlatformError merge_worker_results(ScanWork *works, int n, ScanResults *out);

/* ---- Public API (order matches scanner.h) ---- */

void scan_results_init(ScanResults *results)
{
    if (!results) return;
    results->addresses   = NULL;
    results->values       = NULL;
    results->count        = 0;
    results->capacity     = 0;
    results->value_width  = 0;
}

void scan_results_free(ScanResults *results)
{
    if (!results) return;
    free(results->addresses);
    free(results->values);
    results->addresses  = NULL;
    results->values     = NULL;
    results->count      = 0;
    results->capacity   = 0;
    results->value_width = 0;
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

PlatformError scanner_scan_regions(const ScanSession *session, const ScanRegion *regions, size_t count, ScanResults *out)
{
    unsigned short width = session->param.width;
    int snapshot = 0;
    if (session->mode == SCAN_MODE_UNKNOWN_INITIAL) {
        width = scan_type_width(session->param.type);
        snapshot = 1;
        if (width == 0) return PLATFORM_ERR_INVALID_PARAM;
    } else if (width == 0) {
        return PLATFORM_ERR_INVALID_PARAM;
    }
    return scan_regions(session, regions, count, width, snapshot, out);
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
    int snapshot = 0;
    if (m == SCAN_MODE_UNKNOWN_INITIAL) {
        width = scan_type_width(session->param.type);
        if (width == 0) {
            return PLATFORM_ERR_INVALID_PARAM;  /* unknown-initial needs a fixed-width numeric type */
        }
        session->param.width = width;  /* narrowing needs a byte size to re-read with */
        snapshot = 1;
    }

    /* A first scan discards any prior result set entirely. */
    scan_results_free(&session->results);

    ScanRegion *regions = NULL;
    size_t region_count = 0;
    PlatformError err = scanner_enumerate_regions(session->target, &regions, &region_count);
    if (err != PLATFORM_OK) {
        return err;
    }

    int nthreads = 1;
    if (region_count >= 4) {
        nthreads = (int)(region_count < SCAN_MAX_THREADS ? region_count : SCAN_MAX_THREADS);
    }

    if (nthreads == 1) {
        PlatformError e = scan_regions(session, regions, region_count, width, snapshot, &session->results);
        scanner_free_regions(regions);
        if (e != PLATFORM_OK) {
            return e;
        }
        session->has_results = 1;
        return PLATFORM_OK;
    }

    ScanWork works[SCAN_MAX_THREADS];
    thrd_t   tids[SCAN_MAX_THREADS];
    int      started[SCAN_MAX_THREADS] = {0};

    for (int i = 0; i < nthreads; i++) {
        size_t start = (size_t)i * region_count / (size_t)nthreads;
        size_t end   = (size_t)(i + 1) * region_count / (size_t)nthreads;
        works[i].session  = session;
        works[i].regions  = regions + start;
        works[i].count    = end - start;
        works[i].width    = width;
        works[i].snapshot = snapshot;
        works[i].err      = PLATFORM_OK;
        scan_results_init(&works[i].results);
    }

    for (int i = 0; i < nthreads; i++) {
        if (thrd_create(&tids[i], scan_worker, &works[i]) == thrd_success) {
            started[i] = 1;
        } else {
            works[i].err = scan_regions(session, works[i].regions, works[i].count,
                                        works[i].width, works[i].snapshot, &works[i].results);
        }
    }
    for (int i = 0; i < nthreads; i++) {
        if (started[i]) {
            int dummy;
            thrd_join(tids[i], &dummy);
        }
    }

    PlatformError worst = PLATFORM_OK;
    for (int i = 0; i < nthreads; i++) {
        if (works[i].err != PLATFORM_OK) {
            worst = works[i].err;
        }
    }
    if (worst != PLATFORM_OK) {
        for (int i = 0; i < nthreads; i++) scan_results_free(&works[i].results);
        scanner_free_regions(regions);
        return worst;
    }

    PlatformError me = merge_worker_results(works, nthreads, &session->results);
    scanner_free_regions(regions);
    if (me != PLATFORM_OK) {
        return me;
    }
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
        return PLATFORM_ERR_INVALID_PARAM;
    }

    const size_t W = session->param.width;

    ScanResults *r = &session->results;
    size_t survivors = 0;
    unsigned char cur[SCAN_VALUE_MAX];
    for (size_t i = 0; i < r->count; i++) {
        unsigned long long addr = r->addresses[i];
        unsigned char       *prev = r->values + i * W;
        PlatformError rd = memory_read(session->target, addr, cur, W);
        if (rd != PLATFORM_OK) {
            continue;
        }
        if (keep_hit(session, cur, prev, W)) {
            r->addresses[survivors] = addr;
            memcpy(r->values + survivors * W, cur, W);
            survivors++;
        }
    }
    r->count = survivors;
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
    if (width > SCAN_VALUE_MAX) return 0;
    if (results->value_width == 0) {
        results->value_width = (unsigned short)width;
    } else if (results->value_width != width) {
        return 0;   /* caller mixed widths -- programmer error, refuse silently */
    }

    if (results->count >= results->capacity) {
        size_t new_cap = results->capacity ? results->capacity * 2 : 64;
        unsigned long long *na = (unsigned long long *)realloc(results->addresses, new_cap * sizeof(unsigned long long));
        if (!na) return 0;
        unsigned char *nv = (unsigned char *)realloc(results->values, new_cap * results->value_width);
        if (!nv) {
            free(na);  /* orphan grown buffer; keep the old pair intact */
            return 0;
        }
        results->addresses = na;
        results->values   = nv;
        results->capacity = new_cap;
    }

    results->addresses[results->count] = address;
    memcpy(results->values + results->count * results->value_width, value, results->value_width);
    results->count++;
    return 1;
}

static PlatformError scan_regions(const ScanSession *session, const ScanRegion *regions, size_t count,
                                   unsigned short width, int snapshot, ScanResults *out)
{
    const size_t W = width;
    const ScanValue *want = &session->param;
    unsigned char buf[SCAN_CHUNK_BYTES];

    for (size_t r = 0; r < count; r++) {
        unsigned long long addr = regions[r].base;
        size_t remaining = regions[r].size;

        while (remaining >= W) {
            size_t take = remaining < SCAN_CHUNK_BYTES ? remaining : SCAN_CHUNK_BYTES;
            PlatformError rd = memory_read(session->target, addr, buf, take);
            if (rd != PLATFORM_OK) {
                break;  /* per-region failure: skip the rest of this region */
            }

            size_t last = take - W;
            for (size_t off = 0; off <= last; off++) {
                if (!snapshot && !value_equals(buf + off, want)) {
                    continue;
                }
                if (!scan_results_append(out, addr + off, buf + off, W)) {
                    return PLATFORM_ERR_INTERNAL;
                }
            }

            size_t advance = take - W + 1;
            addr      += advance;
            remaining -= advance;
        }
    }
    return PLATFORM_OK;
}

static int scan_worker(void *arg)
{
    ScanWork *w = (ScanWork *)arg;
    w->err = scan_regions(w->session, w->regions, w->count, w->width, w->snapshot, &w->results);
    return 0;
}

static PlatformError merge_worker_results(ScanWork *works, int n, ScanResults *out)
{
    size_t total = 0;
    for (int i = 0; i < n; i++) total += works[i].results.count;

    /* value_width is set per-worker on its first append; if worker 0 found no
       hits its width is still 0. Scan every worker for a real width before we
       size the merged `values` buffer (else we'd allocate 0 bytes). */
    unsigned short width = 0;
    for (int i = 0; i < n; i++) {
        if (works[i].results.value_width) {
            width = works[i].results.value_width;
            break;
        }
    }

    scan_results_init(out);
    out->value_width = width;
    if (total == 0) {
        for (int i = 0; i < n; i++) scan_results_free(&works[i].results);
        return PLATFORM_OK;
    }
    if (width == 0) {
        /* total > 0 but no worker recorded a width -- inconsistent state. */
        for (int i = 0; i < n; i++) scan_results_free(&works[i].results);
        return PLATFORM_ERR_INTERNAL;
    }

    out->addresses = (unsigned long long *)malloc(total * sizeof(unsigned long long));
    out->values    = (unsigned char *)malloc((size_t)total * width);
    if (!out->addresses || !out->values) {
        free(out->addresses); free(out->values);
        scan_results_init(out);
        for (int i = 0; i < n; i++) scan_results_free(&works[i].results);
        return PLATFORM_ERR_INTERNAL;
    }
    out->capacity = total;

    size_t pos_a = 0;
    size_t pos_v = 0;
    for (int i = 0; i < n; i++) {
        size_t c = works[i].results.count;
        if (c) {
            memcpy(out->addresses + pos_a, works[i].results.addresses, c * sizeof(unsigned long long));
            memcpy(out->values + pos_v, works[i].results.values, c * width);
        }
        pos_a += c;
        pos_v += c * width;
        scan_results_free(&works[i].results);
    }
    out->count = total;
    return PLATFORM_OK;
}