#include "tui_internal.h"
#include "core/pointer_scan/pointer_scan.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <wctype.h>

static struct {
    PointerResults results;
    size_t selected, scroll, horizontal;
    HANDLE worker;
    Target target;
    unsigned long long address;
    unsigned int depth, max_offset;
    atomic_bool cancel;
    PointerResults pending;
    PlatformError error;
} pointers;

static DWORD WINAPI scan_pointers(LPVOID unused);
static void show_results(const wchar_t *action);
static void format_path(wchar_t *line, size_t capacity, const PointerPath *path);

int tui_pointer_is_running(void)
{
    return pointers.worker != NULL;
}

void tui_pointer_start(unsigned long long address, unsigned int depth, unsigned int max_offset)
{
    if (!tui_state.attached) { tui_set_status(L"No process attached", TRUE); return; }
    if (pointers.worker || tui_scan_is_running()) { tui_set_status(L"A scan is already running", TRUE); return; }
    if (!address || !depth || depth > POINTER_MAX_DEPTH || max_offset > POINTER_MAX_OFFSET) {
        tui_set_status(L"Pointers: depth 1-3, offset 0-4096, nonzero address", TRUE);
        return;
    }
    pointers.target = tui_state.target;
    pointers.address = address;
    pointers.depth = depth;
    pointers.max_offset = max_offset;
    atomic_init(&pointers.cancel, false);
    pointers.worker = CreateThread(NULL, 0, scan_pointers, NULL, 0, NULL);
    if (!pointers.worker) { tui_set_status(L"Could not start pointer worker", TRUE); return; }
    tui_state.panel = PANEL_POINTERS;
    tui_state.sidebar_idx = PANEL_POINTERS;
    tui_state.focus = FOCUS_MAIN;
    tui_set_status(L"Scanning pointers...", FALSE);
}

void tui_pointer_poll(void)
{
    if (!pointers.worker || WaitForSingleObject(pointers.worker, 0) != WAIT_OBJECT_0) return;
    CloseHandle(pointers.worker);
    pointers.worker = NULL;
    if (pointers.error != PLATFORM_OK) {
        pointer_results_free(&pointers.pending);
        wchar_t line[192];
        swprintf_s(line, _countof(line), L"Pointer scan failed: %S", process_error_string(pointers.error));
        tui_set_status(line, TRUE);
        return;
    }
    pointer_results_free(&pointers.results);
    pointers.results = pointers.pending;
    pointers.pending = (PointerResults){0};
    pointers.selected = pointers.scroll = pointers.horizontal = 0;
    show_results(L"Pointers");
}

void tui_pointer_cancel(void)
{
    if (pointers.worker) {
        atomic_store(&pointers.cancel, true);
        WaitForSingleObject(pointers.worker, INFINITE);
        CloseHandle(pointers.worker);
        pointers.worker = NULL;
        pointer_results_free(&pointers.pending);
    }
    for (size_t i = 0; i < pointers.results.count; i++) pointers.results.paths[i].resolved_address = 0;
}

void tui_pointer_reset(void)
{
    tui_pointer_cancel();
    pointer_results_free(&pointers.results);
    pointers.selected = pointers.scroll = pointers.horizontal = 0;
}

void tui_pointer_filter(unsigned long long address)
{
    if (!tui_state.attached) { tui_set_status(L"No process attached", TRUE); return; }
    if (pointers.worker) { tui_set_status(L"Wait for pointer scan to finish", TRUE); return; }
    if (!pointers.results.count) { tui_set_status(L"No pointer paths to filter", TRUE); return; }
    PlatformError error = pointer_filter(&tui_state.target, address, &pointers.results);
    if (error != PLATFORM_OK) {
        wchar_t line[192];
        swprintf_s(line, _countof(line), L"Pointer filter failed: %S", process_error_string(error));
        tui_set_status(line, TRUE);
        return;
    }
    pointers.selected = pointers.scroll = pointers.horizontal = 0;
    tui_state.panel = PANEL_POINTERS;
    tui_state.sidebar_idx = PANEL_POINTERS;
    show_results(L"Pointers");
}

void tui_pointer_draw(Screen *screen, int x, int top, int bottom)
{
    WORD normal = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    wchar_t line[512];
    if (top > bottom) return;
    if (pointers.worker) swprintf_s(line, _countof(line), L"Scanning pointers...");
    else swprintf_s(line, _countof(line), L"Pointers: %llu paths%s", (unsigned long long)pointers.results.count,
                    pointers.results.truncated ? L" (PARTIAL)" : L"");
    screen_text(screen, x, top++, line, normal);
    if (top > bottom) return;
    screen_text(screen, x, bottom, pointers.worker ? L"[C] Cancel scan" : L"[R] Resolve [Enter] Hex", normal);
    int rows = bottom - top;
    if (rows <= 0) return;
    if (!pointers.results.count) {
        screen_text(screen, x, top, L"P on a value; pointers <address>", FOREGROUND_INTENSITY);
        return;
    }
    if (pointers.selected < pointers.scroll) pointers.scroll = pointers.selected;
    if (pointers.selected >= pointers.scroll + (size_t)rows) pointers.scroll = pointers.selected - (size_t)rows + 1;
    for (int row = 0; row < rows && pointers.scroll + (size_t)row < pointers.results.count; row++) {
        size_t index = pointers.scroll + (size_t)row;
        format_path(line, _countof(line), &pointers.results.paths[index]);
        size_t length = wcslen(line);
        size_t offset = pointers.horizontal < length ? pointers.horizontal : length;
        screen_text(screen, x, top + row, line + offset, index == pointers.selected ? normal | BACKGROUND_BLUE : normal);
    }
}

void tui_pointer_key(WORD vk, WCHAR ch)
{
    if (ch == L'?') { tui_open_help(); return; }
    if (towlower(ch) == L'c' && pointers.worker) {
        tui_pointer_cancel();
        tui_set_status(L"Pointer scan cancelled; previous paths retained", FALSE);
        return;
    }
    if (vk == VK_LEFT && pointers.horizontal) { pointers.horizontal--; return; }
    if (vk == VK_RIGHT && pointers.results.count) {
        wchar_t line[512];
        format_path(line, _countof(line), &pointers.results.paths[pointers.selected]);
        if (pointers.horizontal + 1 < wcslen(line)) pointers.horizontal++;
        return;
    }
    if (vk == VK_UP && pointers.selected) pointers.selected--;
    else if (vk == VK_DOWN && pointers.selected + 1 < pointers.results.count) pointers.selected++;
    else if ((towlower(ch) == L'r' || vk == VK_RETURN) && pointers.results.count) {
        if (!tui_state.attached) { tui_set_status(L"Attach the same executable to resolve this path", TRUE); return; }
        PointerPath *path = &pointers.results.paths[pointers.selected];
        PlatformError error = pointer_resolve(&tui_state.target, pointers.results.module_name, path);
        wchar_t line[192];
        if (error != PLATFORM_OK) {
            swprintf_s(line, _countof(line), L"Pointer resolution failed: %S", process_error_string(error));
            tui_set_status(line, TRUE);
        } else if (vk == VK_RETURN) tui_hexview_jump(path->resolved_address);
        else {
            swprintf_s(line, _countof(line), L"Pointer resolved: 0x%llX", path->resolved_address);
            tui_set_status(line, FALSE);
        }
    }
}

static DWORD WINAPI scan_pointers(LPVOID unused)
{
    (void)unused;
    pointers.error = pointer_scan(&pointers.target, pointers.address, pointers.depth,
                                   pointers.max_offset, &pointers.cancel, &pointers.pending);
    return 0;
}

static void show_results(const wchar_t *action)
{
    wchar_t line[192];
    swprintf_s(line, _countof(line), L"%s: %llu paths%s; %llu skipped bytes; %llu unreadable paths",
               action, (unsigned long long)pointers.results.count,
               pointers.results.truncated ? L" (PARTIAL: limits reached)" : L"",
               pointers.results.skipped_bytes, (unsigned long long)pointers.results.unreadable_paths);
    tui_set_status(line, FALSE);
}

static void format_path(wchar_t *line, size_t capacity, const PointerPath *path)
{
    _snwprintf_s(line, capacity, _TRUNCATE, L"%s+%llX", pointers.results.module_name, path->root_offset);
    for (unsigned int i = 0; i < path->depth; i++) {
        size_t used = wcslen(line);
        _snwprintf_s(line + used, capacity - used, _TRUNCATE, L" -> +%X", path->offsets[i]);
    }
    size_t used = wcslen(line);
    if (path->resolved_address) _snwprintf_s(line + used, capacity - used, _TRUNCATE, L" = %llX", path->resolved_address);
    else _snwprintf_s(line + used, capacity - used, _TRUNCATE, L" (unresolved)");
}
