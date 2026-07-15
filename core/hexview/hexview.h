#ifndef HEXVIEW_H
#define HEXVIEW_H

#include <stddef.h>
#include "core/memory/memory.h"

/*
 * Read a window of target memory. `bytes` and `readable` are caller-owned,
 * each `size` bytes long. A zero in `readable` means the matching byte has no
 * current value and `bytes` must not be used for it.
 */
PlatformError hexview_read_window(const Target *target, unsigned long long address,
                                  unsigned char *bytes, unsigned char *readable,
                                  size_t size, MemoryRegion *first_region);

PlatformError hexview_write(const Target *target, unsigned long long address,
                            const void *bytes, size_t size);

#endif
