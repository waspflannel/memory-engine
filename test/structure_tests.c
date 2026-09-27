#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "core/structure/structure.h"
#include "test/test.h"

static void test_fields(void)
{
    unsigned char bytes[STRUCTURE_MAX_BYTES] = {0};
    Target target = {0};
    target.handle = GetCurrentProcess();
    StructureWindow window = {0};
    check(structure_open(&window, &target, (unsigned long long)(UINT_PTR)bytes, sizeof(bytes)) == PLATFORM_OK,
          "open full bounded structure window");
    check(structure_open(&window, &target, 0, 0) == PLATFORM_ERR_INVALID_PARAM && window.size == sizeof(bytes),
          "zero size rejected without destroying previous structure");
    check(structure_open(&window, &target, 0, STRUCTURE_MAX_BYTES + 1) == PLATFORM_ERR_INVALID_PARAM,
          "oversized window rejected");
    check(structure_open(&window, &target, ULLONG_MAX - 1, 4) == PLATFORM_ERR_INVALID_PARAM,
          "window address overflow rejected");
    check(structure_set_field(&window, 253, SCAN_TYPE_U32, L"outside") == STRUCTURE_FIELD_INVALID &&
          structure_set_field(&window, SIZE_MAX, SCAN_TYPE_U8, L"overflow") == STRUCTURE_FIELD_INVALID,
          "field extent and offset overflow rejected");
    check(structure_set_field(&window, 0, SCAN_TYPE_STRING, L"string") == STRUCTURE_FIELD_INVALID &&
          structure_set_field(&window, 0, SCAN_TYPE_AOB, L"aob") == STRUCTURE_FIELD_INVALID,
          "only fixed numeric field types accepted");
    wchar_t long_label[STRUCTURE_LABEL_MAX + 1];
    for (size_t i = 0; i < STRUCTURE_LABEL_MAX; i++) long_label[i] = L'x';
    long_label[STRUCTURE_LABEL_MAX] = 0;
    check(structure_set_field(&window, 0, SCAN_TYPE_I32, long_label) == STRUCTURE_FIELD_INVALID &&
          structure_set_field(&window, 0, SCAN_TYPE_I32, L"bad\nlabel") == STRUCTURE_FIELD_INVALID &&
          structure_set_field(&window, 0, SCAN_TYPE_I32, L"") == STRUCTURE_FIELD_INVALID,
          "labels are bounded and single-line");
    for (size_t i = 0; i < STRUCTURE_MAX_FIELDS; i++)
        check(structure_set_field(&window, i, SCAN_TYPE_U8, L"byte") == STRUCTURE_FIELD_OK, "add labelled byte field");
    check(structure_set_field(&window, 100, SCAN_TYPE_F64, L"overflow") == STRUCTURE_FIELD_FULL,
          "field capacity is enforced");
    check(structure_set_field(&window, 0, SCAN_TYPE_F32, L"position") == STRUCTURE_FIELD_OK &&
          window.field_count == STRUCTURE_MAX_FIELDS && window.fields[0].type == SCAN_TYPE_F32 &&
          wcscmp(window.fields[0].label, L"position") == 0,
          "existing offset can change label and type even at capacity");
    check(structure_open(&window, &target, (unsigned long long)(UINT_PTR)bytes, 7) == PLATFORM_OK &&
          window.field_count == 0 && window.size == 7, "new structure clears labels and supports short final rows");
}

static void test_snapshots(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    size_t page_size = info.dwPageSize;
    unsigned char *pages = VirtualAlloc(NULL, page_size * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    check(pages != NULL, "allocate controlled structure pages");
    if (!pages) return;
    memset(pages, 0x11, page_size * 2);
    unsigned char *base = pages + page_size - 128;
    Target target = {0};
    target.handle = GetCurrentProcess();
    StructureWindow window = {0};
    DWORD previous;
    check(structure_open(&window, &target, (unsigned long long)(UINT_PTR)base, 256) == PLATFORM_OK,
          "structure reads across two readable pages");
    int initial_clean = 1;
    for (size_t i = 0; i < window.size; i++)
        if (!window.readable[i] || window.bytes[i] != 0x11 || window.changed[i]) initial_clean = 0;
    check(initial_clean, "initial read is fully known with no invented changes");
    base[3] = 0x22;
    base[129] = 0x33;
    check(structure_refresh(&window, &target) == PLATFORM_OK, "refresh modified structure");
    size_t changed = 0;
    for (size_t i = 0; i < window.size; i++) changed += window.changed[i];
    check(changed == 2 && window.changed[3] && window.changed[129] &&
          window.bytes[3] == 0x22 && window.bytes[129] == 0x33,
          "only actual changed bytes are highlighted");
    check(structure_refresh(&window, &target) == PLATFORM_OK && !window.changed[3] && !window.changed[129],
          "unchanged refresh clears previous change markers");
    check(VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS, &previous), "make second page unreadable");
    check(structure_refresh(&window, &target) == PLATFORM_ERR_PARTIAL_READ &&
          window.readable[127] && !window.readable[128] && !window.readable[255] &&
          !window.changed[129] && window.bytes[129] == 0,
          "partial read retains accessible bytes without exposing stale unreadable data");
    check(VirtualProtect(pages + page_size, page_size, PAGE_READWRITE, &previous), "restore second page");
    base[129] = 0x44;
    check(structure_refresh(&window, &target) == PLATFORM_OK && window.readable[129] &&
          window.bytes[129] == 0x44 && !window.changed[129],
          "newly readable data is not compared against an unknown previous value");
    check(VirtualProtect(pages, page_size, PAGE_READWRITE | PAGE_GUARD, &previous), "guard first page");
    check(structure_refresh(&window, &target) == PLATFORM_ERR_PARTIAL_READ &&
          !window.readable[0] && !window.readable[127] && window.readable[128] && window.bytes[129] == 0x44,
          "guarded prefix is skipped and later readable bytes still inspected");
    MEMORY_BASIC_INFORMATION region;
    check(VirtualQuery(pages, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
          "inspection does not consume target guard protection");
    check(structure_refresh(&window, NULL) == PLATFORM_ERR_INVALID_PARAM &&
          !window.readable[129] && !window.changed[129] && window.bytes[129] == 0,
          "failed refresh invalidates previous snapshot instead of showing stale values");
    VirtualFree(pages, 0, MEM_RELEASE);
}

int main(void)
{
    test_fields();
    test_snapshots();
    printf("structure tests: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
