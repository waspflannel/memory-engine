#include <limits.h>
#include <string.h>
#include <wchar.h>
#include "core/structure/structure.h"
#include "core/hexview/hexview.h"

PlatformError structure_open(StructureWindow *window, const Target *target,
                             unsigned long long address, size_t size)
{
    if (!window || !target || !target->handle || !size || size > STRUCTURE_MAX_BYTES ||
        address > ULLONG_MAX - (size - 1)) return PLATFORM_ERR_INVALID_PARAM;
    *window = (StructureWindow){0};
    window->address = address;
    window->size = size;
    return structure_refresh(window, target);
}

PlatformError structure_refresh(StructureWindow *window, const Target *target)
{
    if (!window || !window->size || window->size > STRUCTURE_MAX_BYTES) return PLATFORM_ERR_INVALID_PARAM;
    unsigned char bytes[STRUCTURE_MAX_BYTES] = {0}, readable[STRUCTURE_MAX_BYTES] = {0};
    MemoryRegion first = {0};
    PlatformError error = hexview_read_window(target, window->address, bytes, readable, window->size, &first);
    int unavailable = 0;
    for (size_t i = 0; i < window->size; i++) {
        window->changed[i] = readable[i] && window->readable[i] && bytes[i] != window->bytes[i];
        window->bytes[i] = readable[i] ? bytes[i] : 0;
        window->readable[i] = readable[i];
        unavailable |= !readable[i];
    }
    return error != PLATFORM_OK ? error : unavailable ? PLATFORM_ERR_PARTIAL_READ : PLATFORM_OK;
}

StructureFieldError structure_set_field(StructureWindow *window, size_t offset,
                                        ScanType type, const wchar_t *label)
{
    size_t width = scanner_type_width(type);
    if (!window || !window->size || !width || !label || !label[0] ||
        wcsnlen_s(label, STRUCTURE_LABEL_MAX) >= STRUCTURE_LABEL_MAX ||
        offset >= window->size || width > window->size - offset) return STRUCTURE_FIELD_INVALID;
    for (const wchar_t *character = label; *character; character++)
        if (*character < L' ' || *character == 0x7f) return STRUCTURE_FIELD_INVALID;
    size_t index = 0;
    while (index < window->field_count && window->fields[index].offset != offset) index++;
    if (index == STRUCTURE_MAX_FIELDS) return STRUCTURE_FIELD_FULL;
    window->fields[index].offset = offset;
    window->fields[index].type = type;
    wcscpy_s(window->fields[index].label, STRUCTURE_LABEL_MAX, label);
    if (index == window->field_count) window->field_count++;
    return STRUCTURE_FIELD_OK;
}
