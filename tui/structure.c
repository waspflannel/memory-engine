#include "tui_internal.h"
#include "core/structure/structure.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>

static StructureWindow window;
static PlatformError read_error;
static int scroll;


static int range_readable(size_t offset, size_t width);
static int range_changed(size_t offset, size_t width);

void tui_structure_open(unsigned long long address, size_t size)
{
    if (!tui_state.attached) { tui_set_status(L"No process attached", TRUE); return; }
    PlatformError error = structure_open(&window, &tui_state.target, address, size);
    if (error == PLATFORM_ERR_INVALID_PARAM) {
        tui_set_status(L"Structure needs a valid address and 1-256 bytes", TRUE);
        return;
    }
    read_error = error;
    scroll = 0;
    tui_state.panel = PANEL_STRUCTURE;
    tui_state.sidebar_idx = PANEL_STRUCTURE;
    tui_state.focus = FOCUS_MAIN;
    tui_state.help_open = 0;
    tui_set_status(error == PLATFORM_OK ? L"Structure opened; R refreshes" : L"Structure contains unreadable bytes", error != PLATFORM_OK);
}

void tui_structure_field(size_t offset, ScanType type, const wchar_t *label)
{
    StructureFieldError error = structure_set_field(&window, offset, type, label);
    tui_set_status(error == STRUCTURE_FIELD_OK ? L"Structure field saved" :
                   error == STRUCTURE_FIELD_FULL ? L"Structure field limit: 32" :
                   L"Field needs an in-range numeric type and a label of 1-63 characters", error != STRUCTURE_FIELD_OK);
}

void tui_structure_refresh(void)
{
    if (!tui_state.attached || !window.size) { tui_set_status(L"Open a structure first", TRUE); return; }
    read_error = structure_refresh(&window, &tui_state.target);
    tui_set_status(read_error == PLATFORM_OK ? L"Structure refreshed; * marks changed bytes" :
                   L"Structure refresh has unreadable bytes", read_error != PLATFORM_OK);
}

void tui_structure_reset(void)
{
    window = (StructureWindow){0};
    read_error = PLATFORM_OK;
    scroll = 0;
}

void tui_structure_draw(Screen *screen, int x, int top, int bottom)
{
    const WORD normal = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    const WORD changed = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    wchar_t lines[STRUCTURE_MAX_FIELDS + STRUCTURE_MAX_BYTES / 4 + 5][192];
    WORD colors[_countof(lines)];
    int count = 0, width = screen->width - x - 1, visible = bottom - top;
    if (width <= 0 || visible <= 0) return;
    if (!window.size) {
        screen_text(screen, x, top, L"structure <hex_address> [size]", normal);
        screen_text(screen, x, top + 1, L"Inspect up to 256 bytes; R refreshes.", normal);
        return;
    }
    swprintf_s(lines[count++], _countof(lines[0]), L"Base %016llX | %zu bytes", window.address, window.size);
    wcscpy_s(lines[count++], _countof(lines[0]), read_error == PLATFORM_OK ?
             L"* Changed since last refresh | Up/Down scroll" : L"Unreadable bytes shown as ??; values unavailable");
    for (size_t i = 0; i < window.field_count; i++) {
        const StructureField *field = &window.fields[i];
        size_t field_width = scanner_type_width(field->type);
        wchar_t value[64];
        int modified = range_changed(field->offset, field_width);
        if (range_readable(field->offset, field_width))
            tui_format_numeric_value(value, _countof(value), field->type, window.bytes + field->offset);
        else wcscpy_s(value, _countof(value), L"unreadable");
        colors[count] = modified ? changed : normal;
        swprintf_s(lines[count++], _countof(lines[0]), L"%c +%04zX %s (%S): %s", modified ? L'*' : L' ',
                   field->offset, field->label, scanner_type_name(field->type), value);
    }
    wcscpy_s(lines[count], _countof(lines[0]), L"Offset | Bytes | i32 | f32");
    colors[count++] = normal;
    for (size_t offset = 0; offset < window.size; offset += 4) {
        size_t row_size = window.size - offset < 4 ? window.size - offset : 4;
        wchar_t hex[13] = L"", number[64] = L"", floating[64] = L"";
        for (size_t i = 0; i < row_size; i++) {
            if (window.readable[offset + i])
                swprintf_s(hex + i * 3, _countof(hex) - i * 3, L"%02X ", window.bytes[offset + i]);
            else wcscpy_s(hex + i * 3, _countof(hex) - i * 3, L"?? ");
        }
        if (row_size == 4 && range_readable(offset, 4)) {
            tui_format_numeric_value(number, _countof(number), SCAN_TYPE_I32, window.bytes + offset);
            tui_format_numeric_value(floating, _countof(floating), SCAN_TYPE_F32, window.bytes + offset);
        } else if (!range_readable(offset, row_size)) wcscpy_s(number, _countof(number), L"unreadable");
        int modified = range_changed(offset, row_size);
        colors[count] = modified ? changed : normal;
        swprintf_s(lines[count++], _countof(lines[0]), L"%c +%04zX %s | %s | %s", modified ? L'*' : L' ',
                   offset, hex, number, floating);
    }
    colors[0] = colors[1] = normal;
    int rows = 0;
    for (int i = 0; i < count; i++) rows += ((int)wcslen(lines[i]) + width - 1) / width;
    int maximum = rows > visible ? rows - visible : 0;
    if (scroll > maximum) scroll = maximum;
    int row = 0;
    for (int i = 0; i < count; i++) {
        int length = (int)wcslen(lines[i]);
        for (int offset = 0; offset < length; offset += width, row++) {
            int y = top + row - scroll;
            if (y < top || y >= bottom) continue;
            for (int column = 0; column < width && offset + column < length; column++)
                screen_put(screen, x + column, y, lines[i][offset + column], colors[i]);
        }
    }
    screen_text(screen, x, bottom, L"[R] Refresh", normal);
}

void tui_structure_key(WORD vk, WCHAR ch)
{
    int page = tui_state.height > 8 ? tui_state.height - 8 : 1;
    if (ch == L'?') tui_open_help();
    else if (towlower(ch) == L'r') tui_structure_refresh();
    else if (vk == VK_UP && scroll > 0) scroll--;
    else if (vk == VK_DOWN) scroll++;
    else if (vk == VK_PRIOR) scroll = scroll > page ? scroll - page : 0;
    else if (vk == VK_NEXT) scroll += page;
}

static int range_readable(size_t offset, size_t width)
{
    for (size_t i = 0; i < width; i++) if (!window.readable[offset + i]) return 0;
    return 1;
}

static int range_changed(size_t offset, size_t width)
{
    for (size_t i = 0; i < width; i++) if (window.changed[offset + i]) return 1;
    return 0;
}
