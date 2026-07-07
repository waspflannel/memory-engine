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
    SCAN_TYPE_I32,
} ScanType;

typedef enum {
    SCAN_MODE_EXACT,
} ScanMode;

typedef struct {
    const Target *target;   /* borrowed, not owned */
    ScanType      type;
    ScanMode      mode;
    int           value_i32;          /* exact-value param for SCAN_TYPE_I32 / SCAN_MODE_EXACT */
    ScanResults   results;
    int           has_results;        /* set after first scan; next scan requires it */
} ScanSession;

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