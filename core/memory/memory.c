#include "core/memory/memory.h"

PlatError mem_read(const Target *target, unsigned long long address, void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return PLAT_ERR_INVALID_PARAM;
    }

    size_t bytes_read = 0;
    return plat_read_memory(target->handle, address, buffer, size, &bytes_read);
}

PlatError mem_write(const Target *target, unsigned long long address, const void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return PLAT_ERR_INVALID_PARAM;
    }

    size_t bytes_written = 0;
    return plat_write_memory(target->handle, address, buffer, size, &bytes_written);
}

PlatError mem_query(const Target *target, unsigned long long address, MemRegion *region)
{
    if (!target || !target->handle || !region) {
        return PLAT_ERR_INVALID_PARAM;
    }

    PlatRegionInfo info = {0};
    PlatError err = plat_query_region(target->handle, address, &info);
    if (err != PLAT_OK) {
        return err;
    }

    region->base    = info.base;
    region->size    = info.size;
    region->protect = info.protect;
    region->state   = info.state;

    return PLAT_OK;
}
