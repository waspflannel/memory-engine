#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <threads.h>
#include <limits.h>
#include "core/scanner/scanner.h"

/* Duplicated Win32 values; the platform layer passes these through raw. */
#define MEM_COMMIT             0x00001000u
#define PAGE_READONLY          0x00000002u
#define PAGE_READWRITE         0x00000004u
#define PAGE_WRITECOPY         0x00000008u
#define PAGE_EXECUTE_READ      0x00000020u
#define PAGE_EXECUTE_READWRITE 0x00000040u
#define PAGE_EXECUTE_WRITECOPY 0x00000080u
#define PAGE_GUARD             0x00000100u

#define SCAN_CHUNK_BYTES 65536

#define SCAN_MAX_THREADS 8

typedef struct ScanWork {
    const ScanSession *session;
    const ScanRegion  *regions;
    size_t             count;
    unsigned short     width;
    ScanResults        results;
    PlatformError      err;
} ScanWork;

typedef struct {
    ScanType type;
    const char *name;
    unsigned short width;
} ScanTypeInfo;

static const ScanTypeInfo s_type_info[] = {
    { SCAN_TYPE_I32, "i32", 4 }, { SCAN_TYPE_I8, "i8", 1 },
    { SCAN_TYPE_I16, "i16", 2 }, { SCAN_TYPE_I64, "i64", 8 },
    { SCAN_TYPE_U8, "u8", 1 }, { SCAN_TYPE_U16, "u16", 2 },
    { SCAN_TYPE_U32, "u32", 4 }, { SCAN_TYPE_U64, "u64", 8 },
    { SCAN_TYPE_F32, "f32", 4 }, { SCAN_TYPE_F64, "f64", 8 },
    { SCAN_TYPE_STRING, "string", 0 }, { SCAN_TYPE_AOB, "aob", 0 },
};

/* Forward declarations — definitions at bottom of file. */
static int  append_hit(ScanResults *results, unsigned long long address);
static PlatformError match_regions(const ScanSession *session, const ScanRegion *regions, size_t count,
                                    unsigned short width, ScanResults *out);
static int  worker_fn(void *arg);
static PlatformError merge_worker_results(ScanWork *works, int n, unsigned short width, ScanResults *out);
static const ScanTypeInfo *find_type(ScanType type);
static int grow_results(ScanResults *results, size_t capacity);
static PlatformError classify_read_failure(const ScanSession *session, PlatformError read_error);
static PlatformError list_regions(const Target *target, ScanRegion **regions, size_t *count,
                                  const atomic_bool *cancel_requested);
static int scan_cancelled(const ScanSession *session);

/* ---- Public API (order matches scanner.h) ---- */

void results_init(ScanResults *results)
{
    if (results) *results = (ScanResults){0};
}

void results_free(ScanResults *results)
{
    if (!results) return;
    free(results->addresses);
    *results = (ScanResults){0};
}

unsigned short scanner_type_width(ScanType type)
{
    const ScanTypeInfo *info = find_type(type);
    return info ? info->width : 0;
}

const char *scanner_type_name(ScanType type)
{
    const ScanTypeInfo *info = find_type(type);
    return info ? info->name : NULL;
}

PlatformError scanner_type_from_name(const char *name, ScanType *type)
{
    if (!name || !type) return PLATFORM_ERR_INVALID_PARAM;
    for (size_t i = 0; i < _countof(s_type_info); i++) {
        if (strcmp(name, s_type_info[i].name) == 0) {
            *type = s_type_info[i].type;
            return PLATFORM_OK;
        }
    }
    return PLATFORM_ERR_INVALID_PARAM;
}

PlatformError scanner_value_set(ScanValue *value, ScanType type, const void *bytes, size_t len)
{
    if (!value || !find_type(type)) return PLATFORM_ERR_INVALID_PARAM;
    value->type = type;
    unsigned short w = scanner_type_width(type);
    if ((w && (!bytes || len < w)) || (!w && (!bytes || len == 0 || len > SCAN_VALUE_MAX))) {
        value->width = 0;
        memset(value->bytes, 0, sizeof(value->bytes));
        return PLATFORM_ERR_INVALID_PARAM;
    }
    value->width = w ? w : (unsigned short)len;
    memcpy(value->bytes, bytes, value->width);
    return PLATFORM_OK;
}

void scanner_session_init(ScanSession *session, const Target *target, ScanType type)
{
    if (!session) return;
    memset(session, 0, sizeof(*session));
    session->target = target;
    session->param.type = type;
    results_init(&session->results);
}

void scanner_session_destroy(ScanSession *session)
{
    if (!session) return;
    results_free(&session->results);
    memset(session, 0, sizeof(*session));
}

PlatformError scanner_find_hits(const ScanSession *session, const ScanRegion *regions, size_t count, ScanResults *out)
{
    if (!session || !session->target || !session->target->handle || !out ||
        (count > 0 && !regions)) return PLATFORM_ERR_INVALID_PARAM;
    unsigned short width = session->param.width;
    if (width == 0) {
        return PLATFORM_ERR_INVALID_PARAM;
    }
    return match_regions(session, regions, count, width, out);
}

PlatformError scanner_first_scan(ScanSession *session)
{
    /* ---- validate ---- */
    if (!session || !session->target || !session->target->handle) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    unsigned short width = session->param.width;
    if (width == 0) {
        return PLATFORM_ERR_INVALID_PARAM;   /* no value set */
    }

    /* Discard any prior result set — a first scan is always a clean start. */
    results_free(&session->results);
    session->has_results = 0;

    /* ---- enumerate every committed, accessible region in the target ---- */
    ScanRegion *regions = NULL;
    size_t region_count = 0;
    PlatformError err = list_regions(session->target, &regions, &region_count, session->cancel_requested);
    if (err != PLATFORM_OK) {
        return err;
    }

    /* ---- decide threading: single-threaded under 4 regions, up to 8 otherwise ---- */
    int nthreads = 1;
    if (region_count >= 4) {
        nthreads = (int)(region_count < SCAN_MAX_THREADS ? region_count : SCAN_MAX_THREADS);
    }

    /* ---- single-threaded path: scan all regions directly ---- */
    if (nthreads == 1) {
        ScanResults new_results;
        results_init(&new_results);
        PlatformError e = match_regions(session, regions, region_count, width, &new_results);
        free(regions);
        if (e != PLATFORM_OK) {
            results_free(&new_results);
            return e;
        }
        session->results = new_results;
        session->results_type = session->param.type;
        session->has_results = 1;
        return PLATFORM_OK;
    }

    /* ---- multi-threaded path: partition regions across workers ---- */
    ScanWork works[SCAN_MAX_THREADS];
    thrd_t   tids[SCAN_MAX_THREADS];
    int      started[SCAN_MAX_THREADS] = {0};

    /* Keep contiguous runs together so overlap never crosses worker ownership. */
    size_t start = 0;
    for (int i = 0; i < nthreads; i++) {
        size_t end   = (size_t)(i + 1) * region_count / (size_t)nthreads;
        if (end < start) end = start;
        while (end < region_count && end > 0 &&
               regions[end - 1].base + regions[end - 1].size == regions[end].base) end++;
        works[i].session  = session;
        works[i].regions  = regions + start;
        works[i].count    = end - start;
        works[i].width    = width;
        works[i].err      = PLATFORM_OK;
        results_init(&works[i].results);
        start = end;
    }

    /* Spawn every worker; a failed create makes the scan fail atomically. */
    for (int i = 0; i < nthreads; i++) {
        if (thrd_create(&tids[i], worker_fn, &works[i]) == thrd_success) {
            started[i] = 1;
        } else {
            works[i].err = PLATFORM_ERR_INTERNAL;
        }
    }

    /* Wait for every spawned thread to finish. */
    for (int i = 0; i < nthreads; i++) {
        if (started[i]) {
            int dummy;
            if (thrd_join(tids[i], &dummy) != thrd_success) {
                works[i].err = PLATFORM_ERR_INTERNAL;
            }
        }
    }

    /* If any worker reported an error, clean up and bail out. */
    PlatformError worst = scan_cancelled(session) ? PLATFORM_ERR_INTERNAL : PLATFORM_OK;
    for (int i = 0; i < nthreads; i++) {
        if (works[i].err != PLATFORM_OK) {
            worst = works[i].err;
        }
    }
    if (worst != PLATFORM_OK) {
        for (int i = 0; i < nthreads; i++) results_free(&works[i].results);
        free(regions);
        return worst;
    }

    /* Merge every worker's hits into a single result set owned by the session. */
    ScanResults new_results;
    results_init(&new_results);
    PlatformError me = merge_worker_results(works, nthreads, width, &new_results);
    memcpy(new_results.value, session->param.bytes, width);
    free(regions);
    if (me != PLATFORM_OK) {
        results_free(&new_results);
        return me;
    }
    session->results = new_results;
    session->results_type = session->param.type;
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
    if (session->param.width == 0 || session->param.width != session->results.value_width ||
        session->param.type != session->results_type) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    const size_t W = session->param.width;

    const ScanResults *previous = &session->results;
    ScanResults survivors;
    results_init(&survivors);
    survivors.value_width = (unsigned short)W;
    memcpy(survivors.value, session->param.bytes, W);
    unsigned char cur[SCAN_VALUE_MAX];
    for (size_t i = 0; i < previous->count; i++) {
        if (scan_cancelled(session)) {
            results_free(&survivors);
            return PLATFORM_ERR_INTERNAL;
        }
        unsigned long long addr = previous->addresses[i];
        PlatformError rd = memory_read(session->target, addr, cur, W);
        if (rd != PLATFORM_OK) {
            PlatformError failure = classify_read_failure(session, rd);
            if (failure != PLATFORM_OK) {
                results_free(&survivors);
                return failure;
            }
            survivors.unreadable_candidates++;
            continue;
        }
        if (memcmp(cur, session->param.bytes, W) == 0) {
            if (!append_hit(&survivors, addr)) {
                results_free(&survivors);
                return PLATFORM_ERR_INTERNAL;
            }
        }
    }
    if (scan_cancelled(session)) {
        results_free(&survivors);
        return PLATFORM_ERR_INTERNAL;
    }
    results_free(&session->results);
    session->results = survivors;
    return PLATFORM_OK;
}

PlatformError scanner_list_regions(const Target *target, ScanRegion **regions, size_t *count)
{
    return list_regions(target, regions, count, NULL);
}

/* ---- Static helpers ---- */

static PlatformError list_regions(const Target *target, ScanRegion **regions, size_t *count,
                                  const atomic_bool *cancel_requested)
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
        if (cancel_requested && atomic_load(cancel_requested)) {
            free(list);
            return PLATFORM_ERR_INTERNAL;
        }
        MemoryRegion info = {0};
        PlatformError err = memory_query(target, address, &info);
        if (err == PLATFORM_ERR_END_OF_ADDRESS_SPACE) {
            break;
        }
        if (err != PLATFORM_OK) {
            free(list);
            return err;
        }

        unsigned int base_protect = info.protect & 0xFFu;
        int committed = (info.state == MEM_COMMIT);
        int readable = base_protect == PAGE_READONLY || base_protect == PAGE_READWRITE ||
                       base_protect == PAGE_WRITECOPY || base_protect == PAGE_EXECUTE_READ ||
                       base_protect == PAGE_EXECUTE_READWRITE ||
                       base_protect == PAGE_EXECUTE_WRITECOPY;
        int accessible = readable && !(info.protect & PAGE_GUARD);
        if (committed && accessible) {
            if (n >= cap) {
                if (cap > SIZE_MAX / 2 || cap * 2 > SIZE_MAX / sizeof(*list)) {
                    free(list);
                    return PLATFORM_ERR_INTERNAL;
                }
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

static int append_hit(ScanResults *results, unsigned long long address)
{
    if (results->count >= results->capacity) {
        size_t new_cap = results->capacity ? results->capacity * 2 : 64;
        if (new_cap < results->capacity || !grow_results(results, new_cap)) return 0;
    }

    results->addresses[results->count] = address;
    results->count++;
    return 1;
}

static PlatformError match_regions(const ScanSession *session, const ScanRegion *regions, size_t count,
                                    unsigned short width, ScanResults *out)
{
    const size_t W = width;
    const ScanValue *want = &session->param;
    unsigned char *buf = (unsigned char *)malloc(SCAN_CHUNK_BYTES + W - 1);
    if (!buf) return PLATFORM_ERR_INTERNAL;

    PlatformError result = PLATFORM_OK;
    out->value_width = width;
    memcpy(out->value, want->bytes, W);
    size_t carry = 0;
    for (size_t r = 0; r < count; r++) {
        if (r > 0 && regions[r - 1].base + regions[r - 1].size != regions[r].base) carry = 0;
        unsigned long long addr = regions[r].base;
        size_t remaining = regions[r].size;

        while (remaining > 0) {
            if (scan_cancelled(session)) {
                result = PLATFORM_ERR_INTERNAL;
                goto done;
            }
            size_t take = remaining < SCAN_CHUNK_BYTES ? remaining : SCAN_CHUNK_BYTES;
            PlatformError rd = memory_read(session->target, addr, buf + carry, take);
            if (rd != PLATFORM_OK) {
                result = classify_read_failure(session, rd);
                if (result == PLATFORM_OK) {
                    out->skipped_regions++;
                    carry = 0;
                    break;
                }
                goto done;
            }

            size_t available = carry + take;
            for (size_t off = 0; off + W <= available; off++) {
                if (memcmp(buf + off, want->bytes, W) != 0) {
                    continue;
                }
                if (!append_hit(out, addr - carry + off)) {
                    result = PLATFORM_ERR_INTERNAL;
                    goto done;
                }
            }

            carry = available < W - 1 ? available : W - 1;
            memmove(buf, buf + available - carry, carry);
            addr      += take;
            remaining -= take;
        }
    }
    if (scan_cancelled(session)) result = PLATFORM_ERR_INTERNAL;
done:
    free(buf);
    return result;
}

static int worker_fn(void *arg)
{
    ScanWork *w = (ScanWork *)arg;
    w->err = match_regions(w->session, w->regions, w->count, w->width, &w->results);
    return 0;
}

static PlatformError merge_worker_results(ScanWork *works, int n, unsigned short width, ScanResults *out)
{
    size_t total = 0;
    size_t skipped_regions = 0;
    for (int i = 0; i < n; i++) {
        if (works[i].results.count > SIZE_MAX - total ||
            works[i].results.skipped_regions > SIZE_MAX - skipped_regions) {
            for (int j = 0; j < n; j++) results_free(&works[j].results);
            return PLATFORM_ERR_INTERNAL;
        }
        total += works[i].results.count;
        skipped_regions += works[i].results.skipped_regions;
    }

    results_init(out);
    out->value_width = width;
    out->skipped_regions = skipped_regions;
    if (total == 0) {
        for (int i = 0; i < n; i++) results_free(&works[i].results);
        return PLATFORM_OK;
    }

    if (total > SIZE_MAX / sizeof(unsigned long long)) {
        for (int i = 0; i < n; i++) results_free(&works[i].results);
        return PLATFORM_ERR_INTERNAL;
    }
    out->addresses = (unsigned long long *)malloc(total * sizeof(unsigned long long));
    if (!out->addresses) {
        results_init(out);
        for (int i = 0; i < n; i++) results_free(&works[i].results);
        return PLATFORM_ERR_INTERNAL;
    }
    out->capacity = total;

    size_t pos_a = 0;
    for (int i = 0; i < n; i++) {
        size_t c = works[i].results.count;
        if (c) {
            memcpy(out->addresses + pos_a, works[i].results.addresses, c * sizeof(unsigned long long));
        }
        pos_a += c;
        results_free(&works[i].results);
    }
    out->count = total;
    return PLATFORM_OK;
}

static const ScanTypeInfo *find_type(ScanType type)
{
    for (size_t i = 0; i < _countof(s_type_info); i++) {
        if (s_type_info[i].type == type) return &s_type_info[i];
    }
    return NULL;
}

static int grow_results(ScanResults *results, size_t capacity)
{
    if (capacity > SIZE_MAX / sizeof(*results->addresses)) return 0;
    unsigned long long *addresses = (unsigned long long *)realloc(results->addresses,
                                                               capacity * sizeof(*addresses));
    if (!addresses) return 0;
    results->addresses = addresses;
    results->capacity = capacity;
    return 1;
}

static int scan_cancelled(const ScanSession *session)
{
    return session->cancel_requested && atomic_load(session->cancel_requested);
}

static PlatformError classify_read_failure(const ScanSession *session, PlatformError read_error)
{
    if (read_error != PLATFORM_ERR_READ_FAILED && read_error != PLATFORM_ERR_PARTIAL_READ) {
        return read_error;
    }

    int alive = 0;
    PlatformError alive_error = process_is_alive(session->target, &alive);
    if (alive_error != PLATFORM_OK) {
        return alive_error;
    }
    if (!alive) {
        return read_error;
    }

    return PLATFORM_OK;
}
