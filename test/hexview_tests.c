#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/hexview/hexview.h"
#include "test/test.h"

static Target current_process_target(void)
{
    Target target = {0};
    target.handle = GetCurrentProcess();
    target.pid = GetCurrentProcessId();
    return target;
}

static void test_boundary_validation(void)
{
    printf("--- hex view boundary validation ---\n");
    Target target = current_process_target();
    unsigned char bytes[4] = {0};
    unsigned char readable[4] = {0};
    MemoryRegion region = {0};

    check(hexview_read_window(NULL, 0, bytes, readable, sizeof(bytes), &region) == PLATFORM_ERR_INVALID_PARAM,
          "window read rejects a NULL target");
    check(hexview_read_window(&target, 0, NULL, readable, sizeof(bytes), &region) == PLATFORM_ERR_INVALID_PARAM,
          "window read rejects a NULL byte buffer");
    check(hexview_read_window(&target, 0, bytes, NULL, sizeof(bytes), &region) == PLATFORM_ERR_INVALID_PARAM,
          "window read rejects a NULL readability buffer");
    check(hexview_read_window(&target, 0, bytes, readable, 0, &region) == PLATFORM_ERR_INVALID_PARAM,
          "window read rejects a zero length");
    check(memory_write(&target, 0, NULL, 1) == PLATFORM_ERR_INVALID_PARAM,
          "window write rejects a NULL byte buffer");
}

static void test_unreadable_window(void)
{
    printf("--- unreadable byte rendering state ---\n");
    SYSTEM_INFO info = {0};
    GetSystemInfo(&info);
    size_t page_size = info.dwPageSize;
    unsigned char *pages = VirtualAlloc(NULL, page_size * 3, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    check(pages != NULL, "three test pages allocate");
    if (!pages) return;

    memset(pages, 0x11, page_size);
    memset(pages + page_size, 0x00, page_size);
    memset(pages + page_size * 2, 0x22, page_size);
    DWORD old_protect = 0;
    check(VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS, &old_protect),
          "middle test page becomes inaccessible");

    Target target = current_process_target();
    size_t window_size = page_size * 3;
    unsigned char *bytes = calloc(window_size, 1);
    unsigned char *readable = calloc(window_size, 1);
    MemoryRegion region = {0};
    check(bytes && readable, "window buffers allocate");
    if (bytes && readable) {
        check(hexview_read_window(&target, (unsigned long long)(UINT_PTR)pages,
                                  bytes, readable, window_size, &region) == PLATFORM_OK,
              "window read spans accessible and inaccessible pages");
        check(region.base == (unsigned long long)(UINT_PTR)pages,
              "window reports the first region metadata");
        check(readable[0] && bytes[0] == 0x11,
              "readable bytes retain their real value");
        check(!readable[page_size] && !readable[page_size + page_size / 2],
              "inaccessible bytes are marked unreadable rather than zero");
        check(readable[page_size * 2] && bytes[page_size * 2] == 0x22,
              "reading resumes after an inaccessible page");
    }

    free(bytes);
    free(readable);
    VirtualProtect(pages + page_size, page_size, old_protect, &old_protect);
    VirtualFree(pages, 0, MEM_RELEASE);
}

static void test_write_and_refresh(void)
{
    printf("--- byte edit and refresh ---\n");
    unsigned char value = 0x10;
    unsigned char replacement = 0xA5;
    unsigned char bytes[1] = {0};
    unsigned char readable[1] = {0};
    MemoryRegion region = {0};
    Target target = current_process_target();

    check(hexview_read_window(&target, (unsigned long long)(UINT_PTR)&value,
                              bytes, readable, sizeof(bytes), &region) == PLATFORM_OK &&
          readable[0] && bytes[0] == value,
          "window reads the current byte");
    check(memory_write(&target, (unsigned long long)(UINT_PTR)&value,
                       &replacement, sizeof(replacement)) == PLATFORM_OK,
          "byte edit writes through core memory");
    check(bytes[0] == 0x10,
          "write does not pretend a cached window refreshed");
    check(hexview_read_window(&target, (unsigned long long)(UINT_PTR)&value,
                              bytes, readable, sizeof(bytes), &region) == PLATFORM_OK &&
          readable[0] && bytes[0] == replacement,
          "post-write window read observes the actual byte");

    SYSTEM_INFO info = {0};
    GetSystemInfo(&info);
    unsigned char *read_only = VirtualAlloc(NULL, info.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    check(read_only != NULL, "read-only test page allocates");
    if (!read_only) return;
    DWORD old_protect = 0;
    check(VirtualProtect(read_only, info.dwPageSize, PAGE_READONLY, &old_protect),
          "test page becomes read-only");
    check(memory_write(&target, (unsigned long long)(UINT_PTR)read_only,
                       &replacement, sizeof(replacement)) == PLATFORM_ERR_WRITE_FAILED,
          "read-only edit returns a clear write failure");
    VirtualProtect(read_only, info.dwPageSize, old_protect, &old_protect);
    VirtualFree(read_only, 0, MEM_RELEASE);
}

int main(void)
{
    test_boundary_validation();
    test_unreadable_window();
    test_write_and_refresh();

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
