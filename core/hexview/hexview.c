#include <limits.h>
#include <string.h>
#include "core/hexview/hexview.h"

/* ---- Public API (order matches hexview.h) ---- */

PlatformError hexview_read_window(const Target *target, unsigned long long address,
                                  unsigned char *bytes, unsigned char *readable,
                                  size_t size, MemoryRegion *first_region)
{
    if (!target || !target->handle || !bytes || !readable || size == 0 || !first_region) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    MemoryRegion region = {0};
    PlatformError err = memory_query(target, address, &region);
    if (err != PLATFORM_OK) return err;
    *first_region = region;

    memset(readable, 0, size);
    unsigned long long current = address;
    size_t remaining = size;
    size_t offset = 0;

    while (remaining > 0) {
        err = memory_query(target, current, &region);
        if (err != PLATFORM_OK) return err;
        if (current < region.base || current - region.base >= region.size) {
            return PLATFORM_ERR_QUERY_FAILED;
        }

        size_t available = region.size - (size_t)(current - region.base);
        size_t segment_size = remaining < available ? remaining : available;
        if (memory_read(target, current, bytes + offset, segment_size) == PLATFORM_OK) {
            memset(readable + offset, 1, segment_size);
        }

        remaining -= segment_size;
        offset += segment_size;
        if (remaining == 0) break;
        if (current > ULLONG_MAX - segment_size) return PLATFORM_ERR_END_OF_ADDRESS_SPACE;
        current += segment_size;
    }

    return PLATFORM_OK;
}

PlatformError hexview_write(const Target *target, unsigned long long address,
                            const void *bytes, size_t size)
{
    return memory_write(target, address, bytes, size);
}
