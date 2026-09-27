#include <limits.h>
#include "core/memory/memory.h"

#define MEM_COMMIT             0x00001000u
#define PAGE_NOACCESS          0x00000001u
#define PAGE_READONLY          0x00000002u
#define PAGE_READWRITE         0x00000004u
#define PAGE_WRITECOPY         0x00000008u
#define PAGE_EXECUTE_READ      0x00000020u
#define PAGE_EXECUTE_READWRITE 0x00000040u
#define PAGE_EXECUTE_WRITECOPY 0x00000080u
#define PAGE_GUARD             0x00000100u

static PlatformError validate_range(const Target *target, unsigned long long address,
                                    size_t size, int require_write);

PlatformError memory_read(const Target *target, unsigned long long address, void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    PlatformError validation = validate_range(target, address, size, 0);
    if (validation != PLATFORM_OK) return validation;

    size_t bytes_read = 0;
    PlatformError err = platform_read_memory(target->handle, address, buffer, size, &bytes_read);
    return err == PLATFORM_OK && bytes_read != size ? PLATFORM_ERR_PARTIAL_READ : err;
}

PlatformError memory_write(const Target *target, unsigned long long address, const void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    PlatformError validation = validate_range(target, address, size, 1);
    if (validation != PLATFORM_OK) return validation;

    size_t bytes_written = 0;
    PlatformError err = platform_write_memory(target->handle, address, buffer, size, &bytes_written);
    return err == PLATFORM_OK && bytes_written != size ? PLATFORM_ERR_PARTIAL_WRITE : err;
}

PlatformError memory_query(const Target *target, unsigned long long address, MemoryRegion *region)
{
    if (!target || !target->handle || !region) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    return platform_query_region(target->handle, address, region);
}

int memory_region_is_readable(const MemoryRegion *region)
{
    unsigned int protect = region->protect & 0xFFu;
    return region->state == MEM_COMMIT && !(region->protect & PAGE_GUARD) &&
           (protect == PAGE_READONLY || protect == PAGE_READWRITE ||
            protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_READ ||
            protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY);
}

static PlatformError validate_range(const Target *target, unsigned long long address,
                                    size_t size, int require_write)
{
    PlatformError access_error = require_write ? PLATFORM_ERR_WRITE_FAILED : PLATFORM_ERR_READ_FAILED;
    PlatformError partial_error = require_write ? PLATFORM_ERR_PARTIAL_WRITE : PLATFORM_ERR_PARTIAL_READ;
    unsigned long long current = address;
    size_t remaining = size;

    while (remaining > 0) {
        MemoryRegion region = {0};
        PlatformError err = memory_query(target, current, &region);
        if (err != PLATFORM_OK) return err;

        if (region.state != MEM_COMMIT || (region.protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
            current < region.base) {
            return remaining == size ? access_error : partial_error;
        }

        unsigned long long offset = current - region.base;
        if (offset >= region.size) {
            return remaining == size ? access_error : partial_error;
        }

        unsigned int base_protect = region.protect & 0xFFu;
        int writable = base_protect == PAGE_READWRITE || base_protect == PAGE_WRITECOPY ||
                       base_protect == PAGE_EXECUTE_READWRITE ||
                       base_protect == PAGE_EXECUTE_WRITECOPY;
        if ((require_write && !writable) || (!require_write && !memory_region_is_readable(&region))) {
            return remaining == size ? access_error : partial_error;
        }

        size_t available = region.size - (size_t)offset;
        if (remaining <= available) return PLATFORM_OK;
        if (current > ULLONG_MAX - available) return partial_error;
        current += available;
        remaining -= available;
    }

    return PLATFORM_OK;
}
