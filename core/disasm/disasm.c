#include <limits.h>
#include <string.h>

#include "vendor/zydis/Zydis.h"
#include "core/disasm/disasm.h"
#include "core/memory/memory.h"

/* Forward declarations — definitions at bottom of file. */
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
        if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &decoded, operands,
                          decoded.operand_count_visible, output->text, sizeof(output->text),
                          output->address, NULL))) {
            return PLATFORM_ERR_INTERNAL;
        }
        find_relative_target(&decoded, operands, output->address, output);

        result->count++;
        offset += decoded.length;
    }

    return PLATFORM_OK;
}

PlatformError disasm_read(const Target *target, unsigned long long address,
                          DisasmResult *result)
{
    if (!target || !target->handle || !result) return PLATFORM_ERR_INVALID_PARAM;

    memset(result, 0, sizeof(*result));
    unsigned char bytes[DISASM_READ_WINDOW_MAX];
    size_t window_size = 0;
    while (window_size < sizeof(bytes)) {
        if (window_size > ULLONG_MAX - address) break;
        unsigned long long current = address + window_size;
        MemoryRegion region = {0};
        PlatformError err = memory_query(target, current, &region);
        if (err == PLATFORM_ERR_END_OF_ADDRESS_SPACE && window_size > 0) break;
        if (err != PLATFORM_OK) return err;
        if (current < region.base || current - region.base >= region.size) {
            return PLATFORM_ERR_QUERY_FAILED;
        }

        if (!memory_region_is_readable(&region)) {
            if (window_size == 0) return PLATFORM_ERR_READ_FAILED;
            break;
        }

        size_t segment_size = region.size - (size_t)(current - region.base);
        if (segment_size > sizeof(bytes) - window_size) segment_size = sizeof(bytes) - window_size;
        err = memory_read(target, current, bytes + window_size, segment_size);
        if (err != PLATFORM_OK) return err;
        window_size += segment_size;
    }
    return disasm_decode_bytes(bytes, window_size, address, result);
}

/* ---- Static helpers ---- */

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
