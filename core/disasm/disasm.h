#ifndef DISASM_H
#define DISASM_H

#include <stddef.h>

#include "core/process/process.h"

#define DISASM_MAX_INSTRUCTION_BYTES 15
#define DISASM_MAX_INSTRUCTIONS      64
#define DISASM_MNEMONIC_MAX          32
#define DISASM_OPERANDS_MAX          256
#define DISASM_READ_WINDOW_MAX       1024

typedef struct {
    unsigned long long address;
    unsigned char      bytes[DISASM_MAX_INSTRUCTION_BYTES];
    unsigned char      length;
    char               mnemonic[DISASM_MNEMONIC_MAX];
    char               operands[DISASM_OPERANDS_MAX];
    int                has_relative_target;
    unsigned long long relative_target;
} DisasmInstruction;

typedef struct {
    DisasmInstruction instructions[DISASM_MAX_INSTRUCTIONS];
    size_t            count;
    int               stopped_at_decode_failure;
    int               has_more;
} DisasmResult;

PlatformError disasm_decode_bytes(const unsigned char *bytes, size_t size,
                                  unsigned long long address, DisasmResult *result);
PlatformError disasm_read(const Target *target, unsigned long long address,
                          DisasmResult *result);

#endif
