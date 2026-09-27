#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>
#include "core/process/process.h"

typedef PlatformRegionInfo MemoryRegion;

PlatformError memory_read(const Target *target, unsigned long long address, void *buffer, size_t size);
PlatformError memory_write(const Target *target, unsigned long long address, const void *buffer, size_t size);
PlatformError memory_query(const Target *target, unsigned long long address, MemoryRegion *region);
int memory_region_is_readable(const MemoryRegion *region);

#endif
