#include "core/memory/memory.h"

PlatformError memory_read(const Target *target, unsigned long long address, void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    size_t bytes_read = 0;
    return platform_read_memory(target->handle, address, buffer, size, &bytes_read);
}

PlatformError memory_write(const Target *target, unsigned long long address, const void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    size_t bytes_written = 0;
    return platform_write_memory(target->handle, address, buffer, size, &bytes_written);
}

PlatformError memory_query(const Target *target, unsigned long long address, MemoryRegion *region)
{
    if (!target || !target->handle || !region) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    PlatformRegionInfo info = {0};
    PlatformError err = platform_query_region(target->handle, address, &info);
    if (err != PLATFORM_OK) {
        return err;
    }

    region->base    = info.base;
    region->size    = info.size;
    region->protect = info.protect;
    region->state   = info.state;

    return PLATFORM_OK;
}
