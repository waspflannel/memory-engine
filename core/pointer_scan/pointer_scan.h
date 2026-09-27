#ifndef POINTER_SCAN_H
#define POINTER_SCAN_H

#include <stdatomic.h>
#include "core/process/process.h"

#define POINTER_MAX_DEPTH 3
/* ponytail: bounded in-memory scan; raise caps only when real targets need it. */
#define POINTER_MAX_OFFSET 4096
/* ponytail: bounded in-memory search; use a disk index only for targets that need larger budgets. */
#define POINTER_MAX_RESULTS 512
#define POINTER_MAX_CANDIDATES 16384
#define POINTER_MAX_INDEX 1048576
#define POINTER_MAX_SCAN_BYTES (256ull * 1024 * 1024)
enum { POINTER_LIMIT_INDEX = 1, POINTER_LIMIT_SCAN = 2,
       POINTER_LIMIT_CANDIDATES = 4, POINTER_LIMIT_RESULTS = 8 };

typedef struct {
    unsigned long long root_offset;
    unsigned int offsets[POINTER_MAX_DEPTH], depth;
    unsigned long long resolved_address; /* Clear on detach or failed resolution. */
} PointerPath;

typedef struct {
    PointerPath *paths;
    size_t count;
    wchar_t module_name[PLATFORM_NAME_MAX];
    unsigned long long scanned_bytes, skipped_bytes;
    size_t unreadable_paths;
    unsigned int truncated;
    int cancelled;
} PointerResults;

/* Initialize results to zero. Scan replaces previous results. Roots belong to
   the main executable; each offset follows one aligned 64-bit dereference. */
PlatformError pointer_scan(const Target *target, unsigned long long address,
                           unsigned int depth, unsigned int max_offset,
                           const atomic_bool *cancel, PointerResults *results);
PlatformError pointer_resolve(const Target *target, const wchar_t *module_name, PointerPath *path);
PlatformError pointer_filter(const Target *target, unsigned long long address, PointerResults *results);
void pointer_results_free(PointerResults *results);

#endif
