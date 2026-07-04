#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "core/memory/memory.h"
#include "platform/platform.h"

int mem_read(const Target *target, unsigned long long address, void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return -1;
    }

    size_t bytes_read = 0;
    PlatError err = plat_read_memory(target->handle, address, buffer, size, &bytes_read);
    if (err != PLAT_OK) {
        return -1;
    }

    return 0;
}

int mem_write(const Target *target, unsigned long long address, const void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return -1;
    }

    size_t bytes_written = 0;
    PlatError err = plat_write_memory(target->handle, address, buffer, size, &bytes_written);
    if (err != PLAT_OK) {
        return -1;
    }

    return 0;
}

int mem_query(const Target *target, unsigned long long address, MemRegion *region)
{
    if (!target || !target->handle || !region) {
        return -1;
    }

    PlatRegionInfo info = {0};
    PlatError err = plat_query_region(target->handle, address, &info);
    if (err != PLAT_OK) {
        return -1;
    }

    region->base    = info.base;
    region->size    = info.size;
    region->protect = info.protect;
    region->state   = info.state;

    return 0;
}
