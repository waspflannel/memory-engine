#include "core/memory/memory.h"

#define MEM_COMMIT             0x00001000u
#define PAGE_NOACCESS          0x00000001u
#define PAGE_READWRITE         0x00000004u
#define PAGE_WRITECOPY         0x00000008u
#define PAGE_EXECUTE_READWRITE 0x00000040u
#define PAGE_EXECUTE_WRITECOPY 0x00000080u
#define PAGE_GUARD             0x00000100u

static PlatformError validate_region(const Target *target, unsigned long long address,
                                     size_t size, int require_write);

PlatformError memory_read(const Target *target, unsigned long long address, void *buffer, size_t size)
{
    if (!target || !target->handle || !buffer || size == 0) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    PlatformError validation = validate_region(target, address, size, 0);
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

    PlatformError validation = validate_region(target, address, size, 1);
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

static PlatformError validate_region(const Target *target, unsigned long long address,
                                     size_t size, int require_write)
{
    MemoryRegion region = {0};
    PlatformError err = memory_query(target, address, &region);
    if (err != PLATFORM_OK) return err;

    if (region.state != MEM_COMMIT || (region.protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
        address < region.base) {
        return require_write ? PLATFORM_ERR_WRITE_FAILED : PLATFORM_ERR_READ_FAILED;
    }

    unsigned long long offset = address - region.base;
    if (offset > region.size || size > region.size - (size_t)offset) {
        return require_write ? PLATFORM_ERR_PARTIAL_WRITE : PLATFORM_ERR_PARTIAL_READ;
    }

    if (require_write) {
        unsigned int base_protect = region.protect & 0xFFu;
        if (base_protect != PAGE_READWRITE && base_protect != PAGE_WRITECOPY &&
            base_protect != PAGE_EXECUTE_READWRITE && base_protect != PAGE_EXECUTE_WRITECOPY) {
            return PLATFORM_ERR_WRITE_FAILED;
        }
    }
    return PLATFORM_OK;
}
