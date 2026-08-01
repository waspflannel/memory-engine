#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
              strcmp(result.instructions[0].mnemonic, "nop") == 0,
              "decode returns the first mnemonic and length");
        check(result.instructions[1].length == 3 &&
              strcmp(result.instructions[1].mnemonic, "mov") == 0,
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

static void test_memory_read(void)
{
    printf("--- target memory read ---\n");
    unsigned char code[] = { 0xCC, 0xC3 };
    DisasmResult result;
    Target target = current_process_target();

    check(disasm_read(&target, (unsigned long long)(UINT_PTR)code, &result) == PLATFORM_OK,
          "disasm reads bytes through core memory");
    check(result.count > 0 && strcmp(result.instructions[0].mnemonic, "int3") == 0,
          "disasm decodes bytes read from the current process");
    check(disasm_read(&target, 0, &result) != PLATFORM_OK,
          "disasm surfaces an unreadable address");
}

int main(void)
{
    test_decode_and_branch_target();
    test_incomplete_instruction();
    test_memory_read();

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
