#ifndef SCANNER_H
#define SCANNER_H

#include <stddef.h>
#include <stdatomic.h>
#include "core/memory/memory.h"

#define SCAN_VALUE_MAX 256  /* max exact value bytes: covers AOB/string up to 256 */

typedef struct {
    unsigned long long base;
    size_t             size;
} ScanRegion;

typedef struct {
    unsigned long long *addresses;
    unsigned char       value[SCAN_VALUE_MAX]; /* identical for every exact-scan hit */
    size_t              count;
    size_t              capacity;
    size_t              skipped_regions;        /* ignored by the latest first scan */
    size_t              unreadable_candidates;  /* removed by the latest next scan */
    unsigned short      value_width;
} ScanResults;

void results_init(ScanResults *results);
void results_free(ScanResults *results);

PlatformError scanner_list_regions(const Target *target, ScanRegion **regions, size_t *count);

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

typedef struct {
    ScanType       type;
    unsigned short width;
    unsigned char  bytes[SCAN_VALUE_MAX];
} ScanValue;

typedef struct {
    const Target *target;   /* borrowed, not owned */
    const atomic_bool *cancel_requested; /* optional, borrowed for the scan lifetime */
    ScanValue     param;        /* value to search for */
    ScanResults   results;
    ScanType      results_type;       /* valid only while has_results is set */
    int           has_results;        /* set after first scan; next scan requires it */
} ScanSession;

unsigned short scanner_type_width(ScanType type);     /* fixed width, or 0 for variable (string/AOB) */
const char    *scanner_type_name(ScanType type);
PlatformError  scanner_type_from_name(const char *name, ScanType *type);

PlatformError scanner_value_set(ScanValue *value, ScanType type, const void *bytes, size_t len);

void           scanner_session_init(ScanSession *session, const Target *target, ScanType type);
void           scanner_session_destroy(ScanSession *session);

PlatformError  scanner_first_scan(ScanSession *session);
PlatformError  scanner_next_scan(ScanSession *session);
PlatformError  scanner_find_hits(const ScanSession *session, const ScanRegion *regions, size_t count, ScanResults *out);

#endif
