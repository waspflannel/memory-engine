#ifndef SCANNER_H
#define SCANNER_H

#include <stddef.h>
#include "core/memory/memory.h"

#define SCAN_VALUE_MAX 256  /* max value bytes per hit: covers AOB/string up to 256 */

/*
 * Phase 2 — memory scanner.
 *
 * Finds addresses in the attached target by value, then narrows the result
 * set across iterative "next" scans (the core loop of the tool). This module
 * enumerates scannable regions, runs first/next scans, and holds the live
 * result set. It uses core/memory for all reads; it never touches Win32 and
 * never renders.
 */

/* Scannable region: a committed, readable span of the target's address space. */
typedef struct {
    unsigned long long base;
    size_t             size;
} ScanRegion;

/* One surviving address plus its last-seen value bytes (width fixed per scan). */
typedef struct {
    unsigned long long address;
    unsigned char      value[SCAN_VALUE_MAX];
} ScanHit;

/* The live result set of a scan session. */
typedef struct {
    ScanHit *hits;
    size_t   count;
    size_t   capacity;
} ScanResults;

void scan_results_init(ScanResults *results);
void scan_results_free(ScanResults *results);
void scan_results_clear(ScanResults *results);

/*
 * Walk the target's address space and collect committed, readable regions
 * (state == MEM_COMMIT, not PAGE_GUARD, not PAGE_NOACCESS). This is the
 * untrusted boundary the phase doc calls out: validate once here, trust the
 * normalized set downstream. Caller owns the returned array.
 */
PlatformError scanner_enumerate_regions(const Target *target, ScanRegion **regions, size_t *count);
void          scanner_free_regions(ScanRegion *regions);

/* Build order: i32/exact first end-to-end, then widen to all types + modes
   (phase-2 doc). Each enum grows as a new type/mode lands -- no speculative
   slots. */

typedef enum {
    SCAN_TYPE_I32,   /* first slice (kept first so existing dispatch stays readable) */
    SCAN_TYPE_I8,
    SCAN_TYPE_I16,
    SCAN_TYPE_I64,
    SCAN_TYPE_U8,
    SCAN_TYPE_U16,
    SCAN_TYPE_U32,
    SCAN_TYPE_U64,
    SCAN_TYPE_F32,
    SCAN_TYPE_F64,
    SCAN_TYPE_STRING,
    SCAN_TYPE_AOB,
} ScanType;

typedef enum {
    SCAN_MODE_EXACT,
} ScanMode;

/*
 * The value the scan compares against, expressed as raw bytes plus a per-byte
 * wildcard mask. For numeric/string types the mask is all-zero (strict compare);
 * for AOB a `??` position sets that byte's mask to 1 and the match ignores it.
 * Integers are stored in the host's little-endian byte order (we compare raw
 * bytes against bytes read from the target, which are also LE on x86/x64).
 */
typedef struct {
    ScanType       type;
    unsigned short width;                       /* bytes compared per hit */
    unsigned char  bytes[SCAN_VALUE_MAX];       /* literal pattern bytes */
    unsigned char  wild[SCAN_VALUE_MAX];        /* 1 = ?? (AOB), 0 = literal */
} ScanValue;

typedef struct {
    const Target *target;   /* borrowed, not owned */
    ScanMode      mode;
    ScanValue     param;        /* exact value / first operand */
    ScanResults   results;
    int           has_results;        /* set after first scan; next scan requires it */
} ScanSession;

unsigned short scan_type_width(ScanType type);     /* fixed width, or 0 for variable (string/AOB) */

void scanner_value_set(ScanValue *value, ScanType type, const void *bytes, size_t len);
void scanner_value_set_wildcard(ScanValue *value, const unsigned char *wild, size_t len);

void           scanner_session_init(ScanSession *session, const Target *target, ScanType type, ScanMode mode);
void           scanner_session_destroy(ScanSession *session);

/* First scan reads every byte offset of every scannable region and keeps
   matches. Next scan re-reads surviving addresses, re-applies the predicate,
   and compacts survivors in place. A failed region read skips that region
   (never fakes zeros); a failed single-address read during narrowing drops
   that hit. */
PlatformError  scanner_first_scan(ScanSession *session);
PlatformError  scanner_next_scan(ScanSession *session);

#endif