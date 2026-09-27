#ifndef POINTER_SCAN_INTERNAL_H
#define POINTER_SCAN_INTERNAL_H

#include "core/pointer_scan/pointer_scan.h"

typedef struct { unsigned long long value, address; } PointerEntry;
typedef struct { PointerEntry *entries; size_t count, capacity; } PointerIndex;

PlatformError pointer_build_index(const Target *target, const PlatformModuleInfo *module,
                                  const atomic_bool *cancel, PointerResults *results, PointerIndex *index);
size_t pointer_index_lower_bound(const PointerIndex *index, unsigned long long value);

#endif
