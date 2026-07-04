#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>
#include "core/process/process.h"

typedef struct {
    unsigned long long base;
    size_t             size;
    unsigned int       protect;
    unsigned int       state;
} MemRegion;

PlatError mem_read(const Target *target, unsigned long long address, void *buffer, size_t size);
PlatError mem_write(const Target *target, unsigned long long address, const void *buffer, size_t size);
PlatError mem_query(const Target *target, unsigned long long address, MemRegion *region);

#endif
