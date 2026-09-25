#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "core/disasm/disasm.h"
#include "test/test.h"

static Target current_process_target(void)
{
    Target target = {0};
    target.handle = GetCurrentProcess();
    target.pid = GetCurrentProcessId();
    return target;
}

static void test_decode_and_branch_target(void)
{
    printf("--- x64 decode and relative target ---\n");
    unsigned char code[] = {
        0x90,
        0x48, 0x89, 0xD8,
        0xE8, 0x05, 0x00, 0x00, 0x00,
        0xEB, 0xFE,
    };
    unsigned long long address = (unsigned long long)(UINT_PTR)code;
    DisasmResult result;

    check(disasm_decode_bytes(code, sizeof(code), address, &result) == PLATFORM_OK,
          "decode accepts a readable x64 byte window");
    check(result.count >= 4, "decode returns the complete instructions");
    if (result.count >= 4) {
        check(result.instructions[0].length == 1 &&
              strcmp(result.instructions[0].text, "nop") == 0,
              "decode returns the first mnemonic and length");
        check(result.instructions[1].length == 3 &&
              strcmp(result.instructions[1].text, "mov rax, rbx") == 0,
              "decode returns a register instruction");
        check(result.instructions[2].length == 5 && result.instructions[2].has_relative_target &&
              result.instructions[2].relative_target == address + 14,
              "relative call target resolves from address plus instruction length");
        check(result.instructions[3].length == 2 && result.instructions[3].has_relative_target &&
              result.instructions[3].relative_target == address + 9,
              "relative jump target resolves backwards");
    }
}

static void test_incomplete_instruction(void)
{
    printf("--- incomplete instruction boundary ---\n");
    const unsigned char code[] = { 0x90, 0xE8, 0x01, 0x00, 0x00 };
    DisasmResult result;

    check(disasm_decode_bytes(code, sizeof(code), 0x1000, &result) == PLATFORM_OK,
          "decode treats a short final instruction as a clean stop");
    check(result.count == 1 && result.stopped_at_decode_failure,
          "incomplete instruction is excluded after the last complete one");
}

static void test_instruction_prefixes(void)
{
    printf("--- instruction prefixes ---\n");
    const unsigned char code[] = { 0xF3, 0xA4, 0xF0, 0x01, 0x18 };
    DisasmResult result;
    check(disasm_decode_bytes(code, sizeof(code), 0x1000, &result) == PLATFORM_OK &&
          result.count == 2, "prefixed instructions decode completely");
    if (result.count == 2) {
        check(strncmp(result.instructions[0].text, "rep movsb", 9) == 0,
              "REP prefix remains in displayed assembly");
        check(strncmp(result.instructions[1].text, "lock add", 8) == 0,
              "LOCK prefix remains in displayed assembly");
    }
}

static void test_readable_region_boundary(void)
{
    printf("--- adjacent readable and inaccessible regions ---\n");
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    size_t page_size = info.dwPageSize;
    unsigned char *pages = VirtualAlloc(NULL, page_size * 3, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE);
    check(pages != NULL, "allocate region boundary fixture");
    if (!pages) return;

    memset(pages, 0x90, page_size * 3);
    const unsigned char call[] = { 0xE8, 0x05, 0x00, 0x00, 0x00 };
    unsigned char *start = pages + page_size - 2;
    memcpy(start, call, sizeof(call));
    pages[page_size * 2 - 2] = 0x90;
    pages[page_size * 2 - 1] = 0xE8;

    DWORD old_protect;
    int protected_pages = VirtualProtect(pages + page_size, page_size, PAGE_READONLY,
                                         &old_protect) &&
                          VirtualProtect(pages + page_size * 2, page_size, PAGE_NOACCESS,
                                         &old_protect);
    check(protected_pages, "split fixture into read-write, read-only and inaccessible regions");
    if (protected_pages) {
        Target target = current_process_target();
        DisasmResult result;
        unsigned long long address = (unsigned long long)(UINT_PTR)start;
        check(disasm_read(&target, address, &result) == PLATFORM_OK,
              "read spans adjacent readable regions");
        check(result.count > 0 && result.instructions[0].length == sizeof(call) &&
              result.instructions[0].has_relative_target &&
              result.instructions[0].relative_target == address + sizeof(call) + 5,
              "split call decodes and retains its relative target");

        address = (unsigned long long)(UINT_PTR)(pages + page_size * 2 - 2);
        check(disasm_read(&target, address, &result) == PLATFORM_OK && result.count == 1 &&
              result.stopped_at_decode_failure,
              "inaccessible boundary excludes an incomplete final instruction");
        check(disasm_read(&target, address + 2, &result) == PLATFORM_ERR_READ_FAILED,
              "inaccessible starting address remains a read failure");
    }
    check(VirtualFree(pages, 0, MEM_RELEASE), "release region boundary fixture");
}

static void test_target_failures(void)
{
    printf("--- target failures ---\n");
    unsigned char code = 0x90;
    unsigned long long address = (unsigned long long)(UINT_PTR)&code;
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    check(handle != NULL, "open a target without read permission");
    if (!handle) return;
    Target target = {0};
    target.handle = handle;
    DisasmResult result;
    check(disasm_read(&target, address, &result) == PLATFORM_ERR_READ_FAILED,
          "read permission failure is surfaced");
    check(CloseHandle(handle), "close restricted target");
    check(disasm_read(&target, address, &result) == PLATFORM_ERR_QUERY_FAILED,
          "invalid target query failure is surfaced");
}

static void test_memory_read(void)
{
    printf("--- target memory read ---\n");
    unsigned char code[] = { 0xCC, 0xC3 };
    DisasmResult result;
    Target target = current_process_target();

    check(disasm_read(&target, (unsigned long long)(UINT_PTR)code, &result) == PLATFORM_OK,
          "disasm reads bytes through core memory");
    check(result.count > 0 && strcmp(result.instructions[0].text, "int3") == 0,
          "disasm decodes bytes read from the current process");
    check(disasm_read(&target, 0, &result) != PLATFORM_OK,
          "disasm surfaces an unreadable address");
    check(disasm_read(&target, ULLONG_MAX, &result) == PLATFORM_ERR_END_OF_ADDRESS_SPACE,
          "disasm rejects a starting address past the application address space");
}

int main(void)
{
    test_decode_and_branch_target();
    test_incomplete_instruction();
    test_instruction_prefixes();
    test_readable_region_boundary();
    test_target_failures();
    test_memory_read();

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
