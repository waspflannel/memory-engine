#include <limits.h>
#include <string.h>

#include "vendor/zydis/Zydis.h"
#include "core/disasm/disasm.h"
#include "core/memory/memory.h"

/* Forward declarations — definitions at bottom of file. */
static PlatformError format_operands(const ZydisFormatter *formatter,
                                     const ZydisDecodedInstruction *instruction,
                                     const ZydisDecodedOperand *operands,
                                     unsigned long long address, char *output,
                                     size_t capacity);
static void find_relative_target(const ZydisDecodedInstruction *instruction,
                                 const ZydisDecodedOperand *operands,
                                 unsigned long long address, DisasmInstruction *output);

/* ---- Public API (order matches disasm.h) ---- */

PlatformError disasm_decode_bytes(const unsigned char *bytes, size_t size,
                                  unsigned long long address, DisasmResult *result)
{
    if (!bytes || size == 0 || size > DISASM_READ_WINDOW_MAX || !result) {
        return PLATFORM_ERR_INVALID_PARAM;
    }

    memset(result, 0, sizeof(*result));

    ZydisDecoder decoder;
    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                       ZYDIS_STACK_WIDTH_64)) ||
        !ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        return PLATFORM_ERR_INTERNAL;
    }

    size_t offset = 0;
    while (offset < size && result->count < DISASM_MAX_INSTRUCTIONS) {
        ZydisDecodedInstruction decoded = {0};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {0};
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, bytes + offset, size - offset,
                                                   &decoded, operands);
        if (!ZYAN_SUCCESS(status)) {
            result->stopped_at_decode_failure = 1;
            break;
        }

        if (decoded.length == 0 || decoded.length > DISASM_MAX_INSTRUCTION_BYTES ||
            offset > ULLONG_MAX - address ||
            (size_t)decoded.length > size - offset) {
            return PLATFORM_ERR_INTERNAL;
        }

        DisasmInstruction *output = &result->instructions[result->count];
        output->address = address + (unsigned long long)offset;
        output->length = decoded.length;
        memcpy(output->bytes, bytes + offset, decoded.length);
        strncpy_s(output->mnemonic, sizeof(output->mnemonic),
                  ZydisMnemonicGetString(decoded.mnemonic), _TRUNCATE);

        PlatformError err = format_operands(&formatter, &decoded, operands, output->address,
                                            output->operands, sizeof(output->operands));
        if (err != PLATFORM_OK) return err;
        find_relative_target(&decoded, operands, output->address, output);

        result->count++;
        offset += decoded.length;
    }

    if (result->count == DISASM_MAX_INSTRUCTIONS && offset < size) {
        result->has_more = 1;
    }
    return PLATFORM_OK;
}

PlatformError disasm_read(const Target *target, unsigned long long address,
                          DisasmResult *result)
{
    if (!target || !target->handle || !result) return PLATFORM_ERR_INVALID_PARAM;

    MemoryRegion region = {0};
    PlatformError err = memory_query(target, address, &region);
    if (err != PLATFORM_OK) return err;
    if (address < region.base || address - region.base >= region.size) {
        return PLATFORM_ERR_QUERY_FAILED;
    }

    size_t window_size = region.size - (size_t)(address - region.base);
    if (window_size > DISASM_READ_WINDOW_MAX) window_size = DISASM_READ_WINDOW_MAX;
    if (window_size == 0) return PLATFORM_ERR_END_OF_ADDRESS_SPACE;

    unsigned char bytes[DISASM_READ_WINDOW_MAX];
    err = memory_read(target, address, bytes, window_size);
    if (err != PLATFORM_OK) return err;
    return disasm_decode_bytes(bytes, window_size, address, result);
}

/* ---- Static helpers ---- */

static PlatformError format_operands(const ZydisFormatter *formatter,
                                     const ZydisDecodedInstruction *instruction,
                                     const ZydisDecodedOperand *operands,
                                     unsigned long long address, char *output,
                                     size_t capacity)
{
    size_t used = 0;
    output[0] = '\0';

    for (ZyanU8 i = 0; i < instruction->operand_count_visible; i++) {
        char operand[DISASM_OPERANDS_MAX];
        if (!ZYAN_SUCCESS(ZydisFormatterFormatOperand(formatter, instruction, &operands[i],
                                                      operand, sizeof(operand), address, NULL))) {
            return PLATFORM_ERR_INTERNAL;
        }

        size_t operand_length = strlen(operand);
        size_t separator_length = used == 0 ? 0 : 2;
        if (separator_length > capacity - used ||
            operand_length > capacity - used - separator_length - 1) {
            return PLATFORM_ERR_INTERNAL;
        }

        if (separator_length != 0) {
            output[used++] = ',';
            output[used++] = ' ';
        }
        memcpy(output + used, operand, operand_length);
        used += operand_length;
        output[used] = '\0';
    }

    return PLATFORM_OK;
}

static void find_relative_target(const ZydisDecodedInstruction *instruction,
                                 const ZydisDecodedOperand *operands,
                                 unsigned long long address, DisasmInstruction *output)
{
    for (ZyanU8 i = 0; i < instruction->operand_count_visible; i++) {
        if (operands[i].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !operands[i].imm.is_relative) {
            continue;
        }

        ZyanU64 target = 0;
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(instruction, &operands[i], address, &target))) {
            output->has_relative_target = 1;
            output->relative_target = target;
            return;
        }
    }
}
