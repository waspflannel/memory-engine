#include "core/address_table/address_table.h"
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define ADDR_TABLE_INIT_CAPACITY 64
#define ADDR_TABLE_LINE_MAX 2048

typedef enum {
    LINE_OK,
    LINE_EOF,
    LINE_TOO_LONG,
    LINE_READ_ERROR,
} LineResult;

typedef struct {
    char label[ADDR_ENTRY_LABEL_MAX];
    ScanType type;
    uintptr_t address;
} ParsedEntry;

/* Forward declarations — definitions at bottom of file. */
static int label_is_valid(const char *label);
static int type_is_supported(ScanType type);
static void invalidate_entries(AddrTable *table);
static int grow_entries(AddrTable *table);
static int write_entry(FILE *file, const AddrEntry *entry);
static LineResult read_line(FILE *file, char *line, size_t capacity);
static int parse_entry_line(const char *line, ParsedEntry *entry);
static int parse_address(const char *start, size_t length, uintptr_t *address);
static int validate_lock_bytes(const char *text, unsigned short width);
static int hex_nibble(char c);

/* ---- Public API (order matches address_table.h) ---- */

int addr_table_init(AddrTable *table, const Target *target)
{
    if (!table) return 0;
    memset(table, 0, sizeof(*table));
    table->target = target;
    table->entries = (AddrEntry *)calloc(ADDR_TABLE_INIT_CAPACITY, sizeof(*table->entries));
    if (!table->entries) return 0;
    table->capacity = ADDR_TABLE_INIT_CAPACITY;
    return 1;
}

void addr_table_destroy(AddrTable *table)
{
    if (!table) return;
    free(table->entries);
    memset(table, 0, sizeof(*table));
}

void addr_table_set_target(AddrTable *table, const Target *target)
{
    if (!table) return;
    invalidate_entries(table);
    table->target = target;
}

int addr_table_add(AddrTable *table, const char *label, ScanType type, uintptr_t address)
{
    if (!table || !table->entries || !label_is_valid(label) ||
        !type_is_supported(type) || address == 0) return -1;

    if (table->count == table->capacity && !grow_entries(table)) return -1;

    AddrEntry *entry = &table->entries[table->count];
    memset(entry, 0, sizeof(*entry));
    strcpy_s(entry->label, ADDR_ENTRY_LABEL_MAX, label);
    entry->type = type;
    entry->address = address;
    table->count++;
    return (int)(table->count - 1);
}

int addr_table_remove(AddrTable *table, size_t index)
{
    if (!table || index >= table->count) return -1;
    if (index + 1 < table->count) {
        memmove(&table->entries[index], &table->entries[index + 1],
                (table->count - index - 1) * sizeof(*table->entries));
    }
    table->count--;
    memset(&table->entries[table->count], 0, sizeof(*table->entries));
    return 0;
}

int addr_table_rename(AddrTable *table, size_t index, const char *label)
{
    if (!table || index >= table->count || !label_is_valid(label)) return -1;
    strcpy_s(table->entries[index].label, ADDR_ENTRY_LABEL_MAX, label);
    return 0;
}

int addr_table_lock(AddrTable *table, size_t index, const void *lock_value)
{
    if (!table || !table->target || !table->target->handle ||
        index >= table->count || !lock_value) return -1;

    AddrEntry *entry = &table->entries[index];
    if (!type_is_supported(entry->type)) return -1;
    memcpy(entry->lock_value, lock_value, scanner_type_width(entry->type));
    entry->locked = true;
    return 0;
}

int addr_table_unlock(AddrTable *table, size_t index)
{
    if (!table || index >= table->count) return -1;
    table->entries[index].locked = false;
    memset(table->entries[index].lock_value, 0, sizeof(table->entries[index].lock_value));
    return 0;
}

PlatformError addr_table_refresh(AddrTable *table)
{
    if (!table) return PLATFORM_ERR_INVALID_PARAM;
    if (!table->target || !table->target->handle) {
        invalidate_entries(table);
        return PLATFORM_ERR_INVALID_PARAM;
    }

    PlatformError first_error = PLATFORM_OK;
    for (size_t i = 0; i < table->count; i++) {
        AddrEntry *entry = &table->entries[i];
        PlatformError err = memory_read(table->target, entry->address,
                                        entry->current_value, scanner_type_width(entry->type));
        entry->value_valid = err == PLATFORM_OK;
        if (err != PLATFORM_OK) {
            memset(entry->current_value, 0, sizeof(entry->current_value));
            if (first_error == PLATFORM_OK) first_error = err;
        }
    }
    return first_error;
}

void addr_table_lock_write(AddrTable *table, bool *had_error, size_t *error_index)
{
    if (!had_error || !error_index) return;
    *had_error = false;
    *error_index = 0;
    if (!table || !table->target || !table->target->handle) return;

    for (size_t i = 0; i < table->count; i++) {
        AddrEntry *entry = &table->entries[i];
        if (!entry->locked) continue;

        PlatformError err = memory_write(table->target, entry->address,
                                         entry->lock_value, scanner_type_width(entry->type));
        if (err != PLATFORM_OK) {
            entry->locked = false;
            memset(entry->lock_value, 0, sizeof(entry->lock_value));
            if (!*had_error) *error_index = i;
            *had_error = true;
        }
    }
}

AddrTableIoError addr_table_save(const AddrTable *table, const wchar_t *filepath)
{
    if (!table || !filepath || !filepath[0]) return ADDR_TABLE_IO_INVALID_PARAM;

    FILE *file = NULL;
    if (_wfopen_s(&file, filepath, L"w") != 0 || !file) return ADDR_TABLE_IO_OPEN_FAILED;

    int failed = fprintf(file, "# MemForge Address Table v1\n") < 0;
    for (size_t i = 0; !failed && i < table->count; i++) {
        failed = !write_entry(file, &table->entries[i]);
    }
    if (!failed && fflush(file) != 0) failed = 1;
    if (fclose(file) != 0) failed = 1;
    return failed ? ADDR_TABLE_IO_WRITE_FAILED : ADDR_TABLE_IO_OK;
}

AddrTableIoError addr_table_load(AddrTable *table, const wchar_t *filepath)
{
    if (!table || !filepath || !filepath[0]) return ADDR_TABLE_IO_INVALID_PARAM;

    FILE *file = NULL;
    if (_wfopen_s(&file, filepath, L"r") != 0 || !file) return ADDR_TABLE_IO_OPEN_FAILED;

    AddrTableIoError result = ADDR_TABLE_IO_OK;
    AddrTable temp;
    int temp_initialized = addr_table_init(&temp, table->target);
    if (!temp_initialized) result = ADDR_TABLE_IO_OUT_OF_MEMORY;

    char line[ADDR_TABLE_LINE_MAX];
    if (result == ADDR_TABLE_IO_OK) {
        LineResult line_result = read_line(file, line, sizeof(line));
        if (line_result == LINE_READ_ERROR) result = ADDR_TABLE_IO_READ_FAILED;
        else if (line_result != LINE_OK || strcmp(line, "# MemForge Address Table v1") != 0) {
            result = ADDR_TABLE_IO_MALFORMED;
        }
    }

    while (result == ADDR_TABLE_IO_OK) {
        LineResult line_result = read_line(file, line, sizeof(line));
        if (line_result == LINE_EOF) break;
        if (line_result == LINE_READ_ERROR) {
            result = ADDR_TABLE_IO_READ_FAILED;
            break;
        }
        if (line_result == LINE_TOO_LONG) {
            result = ADDR_TABLE_IO_MALFORMED;
            break;
        }
        if (line[0] == '\0' || line[0] == '#') continue;

        ParsedEntry parsed = {0};
        if (!parse_entry_line(line, &parsed)) {
            result = ADDR_TABLE_IO_MALFORMED;
            break;
        }
        if (addr_table_add(&temp, parsed.label, parsed.type, parsed.address) < 0) {
            result = ADDR_TABLE_IO_OUT_OF_MEMORY;
            break;
        }
    }

    if (fclose(file) != 0 && result == ADDR_TABLE_IO_OK) result = ADDR_TABLE_IO_READ_FAILED;
    if (result != ADDR_TABLE_IO_OK) {
        if (temp_initialized) addr_table_destroy(&temp);
        return result;
    }

    addr_table_destroy(table);
    *table = temp;
    return ADDR_TABLE_IO_OK;
}

const char *addr_table_io_error_string(AddrTableIoError error)
{
    switch (error) {
    case ADDR_TABLE_IO_OK:            return "no error";
    case ADDR_TABLE_IO_INVALID_PARAM: return "invalid path or table";
    case ADDR_TABLE_IO_OPEN_FAILED:   return "cannot open file";
    case ADDR_TABLE_IO_MALFORMED:     return "malformed address table";
    case ADDR_TABLE_IO_READ_FAILED:   return "failed to read address table";
    case ADDR_TABLE_IO_WRITE_FAILED:  return "failed to write address table";
    case ADDR_TABLE_IO_OUT_OF_MEMORY: return "out of memory";
    default:                          return "unknown address table error";
    }
}

/* ---- Static helpers ---- */

static int label_is_valid(const char *label)
{
    if (!label || !label[0] || strlen(label) >= ADDR_ENTRY_LABEL_MAX) return 0;
    return !strchr(label, '"') && !strchr(label, '\r') && !strchr(label, '\n');
}

static int type_is_supported(ScanType type)
{
    unsigned short width = scanner_type_width(type);
    return scanner_type_name(type) && width > 0 && width <= ADDR_ENTRY_VALUE_MAX;
}

static void invalidate_entries(AddrTable *table)
{
    for (size_t i = 0; i < table->count; i++) {
        AddrEntry *entry = &table->entries[i];
        entry->locked = false;
        entry->value_valid = false;
        memset(entry->current_value, 0, sizeof(entry->current_value));
        memset(entry->lock_value, 0, sizeof(entry->lock_value));
    }
}

static int grow_entries(AddrTable *table)
{
    if (table->capacity > SIZE_MAX / 2 ||
        table->capacity * 2 > SIZE_MAX / sizeof(*table->entries)) return 0;
    size_t new_capacity = table->capacity * 2;
    AddrEntry *grown = (AddrEntry *)realloc(table->entries, new_capacity * sizeof(*grown));
    if (!grown) return 0;
    memset(grown + table->capacity, 0,
           (new_capacity - table->capacity) * sizeof(*grown));
    table->entries = grown;
    table->capacity = new_capacity;
    return 1;
}

static int write_entry(FILE *file, const AddrEntry *entry)
{
    const char *type_name = scanner_type_name(entry->type);
    if (!label_is_valid(entry->label) || !type_is_supported(entry->type) || !type_name ||
        entry->address == 0) return 0;

    if (fprintf(file, "entry \"%s\" %s 0x%" PRIxPTR " %d",
                entry->label, type_name, entry->address, entry->locked ? 1 : 0) < 0) return 0;
    if (entry->locked) {
        if (fputc(' ', file) == EOF) return 0;
        for (unsigned short i = 0; i < scanner_type_width(entry->type); i++) {
            if (fprintf(file, "%02X", entry->lock_value[i]) < 0) return 0;
        }
    }
    return fputc('\n', file) != EOF;
}

static LineResult read_line(FILE *file, char *line, size_t capacity)
{
    if (!fgets(line, (int)capacity, file)) return ferror(file) ? LINE_READ_ERROR : LINE_EOF;

    size_t length = strlen(line);
    if (length > 0 && line[length - 1] == '\n') {
        line[--length] = '\0';
        if (length > 0 && line[length - 1] == '\r') line[--length] = '\0';
    } else if (!feof(file)) {
        return LINE_TOO_LONG;
    }
    if (strchr(line, '\r') || strchr(line, '\n')) return LINE_TOO_LONG;
    return LINE_OK;
}

static int parse_entry_line(const char *line, ParsedEntry *entry)
{
    const char *p = line;
    if (strncmp(p, "entry", 5) != 0 || p[5] != ' ') return 0;
    p += 5;
    while (*p == ' ') p++;
    if (*p++ != '"') return 0;

    const char *label_start = p;
    const char *label_end = strchr(label_start, '"');
    if (!label_end) return 0;
    size_t label_length = (size_t)(label_end - label_start);
    if (label_length == 0 || label_length >= sizeof(entry->label)) return 0;
    memcpy(entry->label, label_start, label_length);
    entry->label[label_length] = '\0';
    if (!label_is_valid(entry->label)) return 0;

    p = label_end + 1;
    if (*p != ' ') return 0;
    while (*p == ' ') p++;

    const char *type_start = p;
    while (*p && *p != ' ') p++;
    size_t type_length = (size_t)(p - type_start);
    if (type_length == 0 || type_length >= 16 || *p != ' ') return 0;
    char type_name[16];
    memcpy(type_name, type_start, type_length);
    type_name[type_length] = '\0';
    if (scanner_type_from_name(type_name, &entry->type) != PLATFORM_OK ||
        !type_is_supported(entry->type)) return 0;
    while (*p == ' ') p++;

    const char *address_start = p;
    while (*p && *p != ' ') p++;
    size_t address_length = (size_t)(p - address_start);
    if (address_length == 0 || *p != ' ' ||
        !parse_address(address_start, address_length, &entry->address)) return 0;
    while (*p == ' ') p++;

    int locked = 0;
    if (*p == '0') locked = 0;
    else if (*p == '1') locked = 1;
    else return 0;
    p++;
    if (*p != '\0' && *p != ' ') return 0;
    while (*p == ' ') p++;

    if (!locked) return *p == '\0';
    return validate_lock_bytes(p, scanner_type_width(entry->type));
}

static int parse_address(const char *start, size_t length, uintptr_t *address)
{
    if (!start || !address || length == 0 || length >= 32 || start[0] == '-' || start[0] == '+') return 0;
    char text[32];
    memcpy(text, start, length);
    text[length] = '\0';

    const char *digits = text;
    if (length >= 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) digits += 2;
    if (!digits[0]) return 0;
    for (const char *p = digits; *p; p++) if (hex_nibble(*p) < 0) return 0;

    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 16);
    if (errno == ERANGE || end == text || *end != '\0' || parsed == 0 ||
        parsed > (unsigned long long)UINTPTR_MAX) return 0;
    *address = (uintptr_t)parsed;
    return 1;
}

static int validate_lock_bytes(const char *text, unsigned short width)
{
    size_t hex_length = (size_t)width * 2;
    for (size_t i = 0; i < hex_length; i++) {
        if (!text[i] || hex_nibble(text[i]) < 0) return 0;
    }
    text += hex_length;
    while (*text == ' ') text++;
    return *text == '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
