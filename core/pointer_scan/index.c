#include <stdlib.h>
#include <string.h>
#include "core/pointer_scan/pointer_internal.h"
#include "core/scanner/scanner.h"

static PlatformError read_region(const Target *target, ScanRegion region, const atomic_bool *cancel,
                                 PointerResults *results, PointerIndex *index, unsigned long long max_address);
static int compare_entries(const void *left, const void *right);

PlatformError pointer_build_index(const Target *target, const PlatformModuleInfo *module,
                                  const atomic_bool *cancel, PointerResults *results, PointerIndex *index)
{
    ScanRegion *regions = NULL;
    size_t count = 0;
    PlatformError error = scanner_list_regions(target, &regions, &count);
    if (error != PLATFORM_OK) return error;
    unsigned long long max_address = 0;
    for (size_t i = 0; i < count; i++) {
        unsigned long long end = regions[i].base + regions[i].size;
        if (end > max_address && end >= regions[i].base) max_address = end;
    }
    /* Visit the executable first so the byte budget cannot exclude all roots. */
    for (unsigned int pass = 0; pass < 2 && error == PLATFORM_OK; pass++) {
        for (size_t i = 0; i < count; i++) {
            int in_module = regions[i].base >= module->base && regions[i].base - module->base < module->size;
            if (in_module != (pass == 0)) continue;
            if (cancel && atomic_load(cancel)) { results->cancelled = 1; break; }
            error = read_region(target, regions[i], cancel, results, index, max_address);
            if (error != PLATFORM_OK || results->cancelled || results->truncated) break;
        }
        if (results->cancelled || results->truncated) break;
    }
    free(regions);
    if (error == PLATFORM_OK && !results->cancelled && index->count > 1)
        qsort(index->entries, index->count, sizeof(*index->entries), compare_entries);
    return error;
}

size_t pointer_index_lower_bound(const PointerIndex *index, unsigned long long value)
{
    size_t low = 0, high = index->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (index->entries[middle].value < value) low = middle + 1;
        else high = middle;
    }
    return low;
}

static PlatformError read_region(const Target *target, ScanRegion region, const atomic_bool *cancel,
                                 PointerResults *results, PointerIndex *index, unsigned long long max_address)
{
    unsigned char bytes[4096];
    unsigned long long cursor = (region.base + 7) & ~7ull;
    unsigned long long end = region.base + region.size;
    if (end < region.base || cursor < region.base) return PLATFORM_ERR_QUERY_FAILED;
    while (cursor < end && end - cursor >= 8) {
        if (cancel && atomic_load(cancel)) { results->cancelled = 1; break; }
        if (results->scanned_bytes >= POINTER_MAX_SCAN_BYTES) {
            results->truncated |= POINTER_LIMIT_SCAN;
            break;
        }
        size_t count = end - cursor < sizeof(bytes) ? (size_t)(end - cursor) : sizeof(bytes);
        if (count > POINTER_MAX_SCAN_BYTES - results->scanned_bytes)
            count = (size_t)(POINTER_MAX_SCAN_BYTES - results->scanned_bytes);
        count &= ~(size_t)7;
        if (!count) { results->truncated |= POINTER_LIMIT_SCAN; break; }
        results->scanned_bytes += count;
        if (memory_read(target, cursor, bytes, count) != PLATFORM_OK) {
            results->skipped_bytes += count;
            cursor += count;
            continue;
        }
        for (size_t offset = 0; offset < count; offset += 8) {
            unsigned long long value;
            memcpy(&value, bytes + offset, sizeof(value));
            if (value < 0x10000 || value >= max_address) continue;
            if (index->count == POINTER_MAX_INDEX) {
                results->truncated |= POINTER_LIMIT_INDEX;
                return PLATFORM_OK;
            }
            if (index->count == index->capacity) {
                size_t capacity = index->capacity ? index->capacity * 2 : 4096;
                PointerEntry *grown = realloc(index->entries, capacity * sizeof(*grown));
                if (!grown) return PLATFORM_ERR_INTERNAL;
                index->entries = grown;
                index->capacity = capacity;
            }
            index->entries[index->count++] = (PointerEntry){value, cursor + offset};
        }
        cursor += count;
    }
    return PLATFORM_OK;
}

static int compare_entries(const void *left, const void *right)
{
    const PointerEntry *first = left, *second = right;
    if (first->value != second->value) return first->value < second->value ? -1 : 1;
    return first->address < second->address ? -1 : first->address > second->address;
}
