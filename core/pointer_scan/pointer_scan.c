#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <limits.h>
#include "core/pointer_scan/pointer_internal.h"
#include "core/memory/memory.h"
#include "platform/debugger.h"

typedef struct {
    unsigned long long address;
    unsigned int offsets[POINTER_MAX_DEPTH];
} PointerCandidate;

static PlatformError load_module(const Target *target, const wchar_t *name, PlatformModuleInfo *module);
static PlatformError resolve_path(const Target *target, const PlatformModuleInfo *module, PointerPath *path);
static void find_paths(const PointerIndex *index, const PlatformModuleInfo *module,
                       unsigned long long address, unsigned int depth, unsigned int max_offset,
                       const atomic_bool *cancel, PointerResults *results,
                       PointerCandidate *current, PointerCandidate *next);

PlatformError pointer_scan(const Target *target, unsigned long long address,
                           unsigned int depth, unsigned int max_offset,
                           const atomic_bool *cancel, PointerResults *results)
{
    if (!results || !address || depth < 1 || depth > POINTER_MAX_DEPTH || max_offset > POINTER_MAX_OFFSET)
        return PLATFORM_ERR_INVALID_PARAM;
    PlatformModuleInfo module;
    PlatformError error = load_module(target, NULL, &module);
    if (error != PLATFORM_OK) return error;
    unsigned char byte;
    error = memory_read(target, address, &byte, 1);
    if (error != PLATFORM_OK) return error;
    pointer_results_free(results);
    wcscpy_s(results->module_name, PLATFORM_NAME_MAX, module.name);
    if (cancel && atomic_load(cancel)) { results->cancelled = 1; return PLATFORM_OK; }
    PointerIndex index = {0};
    error = pointer_build_index(target, &module, cancel, results, &index);
    if (error == PLATFORM_OK && !results->cancelled) {
        PointerCandidate *current = calloc(POINTER_MAX_CANDIDATES, sizeof(*current));
        PointerCandidate *next = malloc(POINTER_MAX_CANDIDATES * sizeof(*next));
        results->paths = malloc(POINTER_MAX_RESULTS * sizeof(*results->paths));
        if (!current || !next || !results->paths) error = PLATFORM_ERR_INTERNAL;
        else find_paths(&index, &module, address, depth, max_offset, cancel, results, current, next);
        free(current);
        free(next);
    }
    free(index.entries);
    return error;
}

PlatformError pointer_resolve(const Target *target, const wchar_t *module_name, PointerPath *path)
{
    if (!path || !module_name) return PLATFORM_ERR_INVALID_PARAM;
    path->resolved_address = 0;
    PlatformModuleInfo module;
    PlatformError error = load_module(target, module_name, &module);
    return error == PLATFORM_OK ? resolve_path(target, &module, path) : error;
}

PlatformError pointer_filter(const Target *target, unsigned long long address, PointerResults *results)
{
    if (!results || !address) return PLATFORM_ERR_INVALID_PARAM;
    for (size_t i = 0; i < results->count; i++) results->paths[i].resolved_address = 0;
    PlatformModuleInfo module;
    PlatformError error = load_module(target, results->module_name, &module);
    if (error != PLATFORM_OK) return error;
    size_t kept = 0;
    results->unreadable_paths = 0;
    for (size_t i = 0; i < results->count; i++) {
        PointerPath path = results->paths[i];
        if (resolve_path(target, &module, &path) != PLATFORM_OK) results->unreadable_paths++;
        else if (path.resolved_address == address) results->paths[kept++] = path;
    }
    results->count = kept;
    return PLATFORM_OK;
}

void pointer_results_free(PointerResults *results)
{
    if (!results) return;
    free(results->paths);
    *results = (PointerResults){0};
}

static PlatformError load_module(const Target *target, const wchar_t *name, PlatformModuleInfo *module)
{
    if (!target || !target->handle) return PLATFORM_ERR_INVALID_PARAM;
    int supported = 0;
    PlatformError error = platform_debug_supported(target->handle, target->pid, &supported);
    if (error != PLATFORM_OK) return error;
    if (!supported) return PLATFORM_ERR_INVALID_PARAM;
    error = platform_get_main_module(target->handle, module);
    if (error == PLATFORM_OK && name && _wcsicmp(module->name, name)) return PLATFORM_ERR_MODULE_FAILED;
    return error;
}

static PlatformError resolve_path(const Target *target, const PlatformModuleInfo *module, PointerPath *path)
{
    path->resolved_address = 0;
    if (path->depth < 1 || path->depth > POINTER_MAX_DEPTH || module->size < 8 ||
        path->root_offset > module->size - 8 || (path->root_offset & 7)) return PLATFORM_ERR_INVALID_PARAM;
    unsigned long long address = module->base + path->root_offset;
    for (unsigned int i = 0; i < path->depth; i++) {
        unsigned long long pointer;
        if ((address & 7) || path->offsets[i] > POINTER_MAX_OFFSET) return PLATFORM_ERR_INVALID_PARAM;
        PlatformError error = memory_read(target, address, &pointer, sizeof(pointer));
        if (error != PLATFORM_OK) return error;
        if (!pointer || pointer > ULLONG_MAX - path->offsets[i]) return PLATFORM_ERR_READ_FAILED;
        address = pointer + path->offsets[i];
    }
    unsigned char byte;
    PlatformError error = memory_read(target, address, &byte, 1);
    if (error == PLATFORM_OK) path->resolved_address = address;
    return error;
}

static void find_paths(const PointerIndex *index, const PlatformModuleInfo *module,
                       unsigned long long address, unsigned int depth, unsigned int max_offset,
                       const atomic_bool *cancel, PointerResults *results,
                       PointerCandidate *current, PointerCandidate *next)
{
    current[0].address = address;
    size_t count = 1;
    for (unsigned int level = 0; level < depth && count; level++) {
        size_t next_count = 0, examined = 0;
        int full = 0;
        for (size_t i = 0; i < count && !full; i++) {
            if (cancel && atomic_load(cancel)) { results->cancelled = 1; return; }
            unsigned long long minimum = current[i].address > max_offset ? current[i].address - max_offset : 0;
            for (size_t hit = pointer_index_lower_bound(index, minimum); hit < index->count; hit++) {
                const PointerEntry *entry = &index->entries[hit];
                if (entry->value > current[i].address) break;
                if (examined++ == POINTER_MAX_CANDIDATES) {
                    results->truncated |= POINTER_LIMIT_CANDIDATES;
                    full = 1;
                    break;
                }
                if (cancel && atomic_load(cancel)) { results->cancelled = 1; return; }
                PointerCandidate candidate = {0};
                candidate.address = entry->address;
                candidate.offsets[0] = (unsigned int)(current[i].address - entry->value);
                memcpy(candidate.offsets + 1, current[i].offsets, level * sizeof(unsigned int));
                if (entry->address >= module->base && module->size >= 8 &&
                    entry->address - module->base <= module->size - 8) {
                    if (results->count == POINTER_MAX_RESULTS) {
                        results->truncated |= POINTER_LIMIT_RESULTS;
                        return;
                    }
                    PointerPath *path = &results->paths[results->count++];
                    *path = (PointerPath){0};
                    path->root_offset = entry->address - module->base;
                    path->depth = level + 1;
                    memcpy(path->offsets, candidate.offsets, sizeof(path->offsets));
                    path->resolved_address = address;
                }
                if (level + 1 < depth) next[next_count++] = candidate;
            }
        }
        PointerCandidate *swap = current;
        current = next;
        next = swap;
        count = next_count;
    }
}
