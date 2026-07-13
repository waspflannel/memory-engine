#include "core/address_table/address_table.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#define ADDR_TABLE_INIT_CAPACITY 64

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_byte(const char *hex)
{
    int hi = hex_nibble(hex[0]);
    int lo = hex_nibble(hex[1]);
    if (hi < 0 || lo < 0) return -1;
    return (hi << 4) | lo;
}

/* ---- Public API (order matches address_table.h) ---- */

void addr_table_init(AddrTable *table, const Target *target)
{
    memset(table, 0, sizeof(*table));
    table->target = target;
    table->entries = (AddrEntry *)calloc(ADDR_TABLE_INIT_CAPACITY, sizeof(AddrEntry));
    if (table->entries) {
        table->capacity = ADDR_TABLE_INIT_CAPACITY;
    }
}

void addr_table_destroy(AddrTable *table)
{
    if (table->entries) {
        free(table->entries);
        table->entries = NULL;
    }
    table->count    = 0;
    table->capacity = 0;
    table->target   = NULL;
}

void addr_table_set_target(AddrTable *table, const Target *target)
{
    if (!table || table->target == target) return;
    for (size_t i = 0; i < table->count; i++) {
        table->entries[i].locked = false;
        table->entries[i].value_valid = false;
        memset(table->entries[i].current_value, 0, sizeof(table->entries[i].current_value));
    }
    table->target = target;
}

int addr_table_add(AddrTable *table, const char *label, ScanType type, uintptr_t address)
{
    if (!table || !label || !label[0] || !scanner_type_name(type) || address == 0) return -1;
    if (strchr(label, '"') || strchr(label, '\r') || strchr(label, '\n') || strlen(label) >= ADDR_ENTRY_LABEL_MAX) return -1;
    if (!table->entries) return -1;

    if (table->count >= table->capacity) {
        size_t new_cap = table->capacity * 2;
        void *grown = realloc(table->entries, new_cap * sizeof(AddrEntry));
        if (!grown) return -1;
        table->entries = (AddrEntry *)grown;
        memset(table->entries + table->capacity, 0,
               (new_cap - table->capacity) * sizeof(AddrEntry));
        table->capacity = new_cap;
    }

    AddrEntry *entry = &table->entries[table->count];
    memset(entry, 0, sizeof(*entry));
    strncpy_s(entry->label, ADDR_ENTRY_LABEL_MAX, label, _TRUNCATE);
    entry->type    = type;
    entry->address = address;
    entry->locked  = false;
    entry->value_valid = false;
    entry->value_width = scanner_type_width(type);
    table->count++;
    return (int)(table->count - 1);
}

int addr_table_remove(AddrTable *table, size_t index)
{
    if (!table || index >= table->count) return -1;

    if (index < table->count - 1) {
        memmove(&table->entries[index], &table->entries[index + 1],
                (table->count - index - 1) * sizeof(AddrEntry));
    }
    table->count--;
    return 0;
}

int addr_table_rename(AddrTable *table, size_t index, const char *label)
{
    if (!table || index >= table->count || !label || !label[0] || strchr(label, '"') ||
        strchr(label, '\r') || strchr(label, '\n') || strlen(label) >= ADDR_ENTRY_LABEL_MAX) return -1;

    strncpy_s(table->entries[index].label, ADDR_ENTRY_LABEL_MAX, label, _TRUNCATE);
    return 0;
}

int addr_table_lock(AddrTable *table, size_t index, const void *lock_value)
{
    if (!table || !table->target || !table->target->handle || index >= table->count || !lock_value) return -1;

    AddrEntry *entry = &table->entries[index];
    unsigned short width = entry->value_width;
    if (width == 0 || width > ADDR_ENTRY_VALUE_MAX) return -1;

    memcpy(entry->lock_value, lock_value, width);
    entry->locked = true;
    return 0;
}

int addr_table_unlock(AddrTable *table, size_t index)
{
    if (!table || index >= table->count) return -1;

    table->entries[index].locked = false;
    return 0;
}

void addr_table_refresh(AddrTable *table)
{
    if (!table || !table->target || !table->target->handle) return;

    for (size_t i = 0; i < table->count; i++) {
        AddrEntry *entry = &table->entries[i];
        if (entry->value_width == 0) {
            entry->value_valid = false;
            continue;
        }

        PlatformError err = memory_read(table->target, entry->address,
                                        entry->current_value, entry->value_width);
        entry->value_valid = (err == PLATFORM_OK);
    }
}

void addr_table_lock_write(AddrTable *table, bool *had_error, size_t *error_index)
{
    if (!had_error || !error_index) return;
    *had_error = false;

    if (!table || !table->target || !table->target->handle) return;

    for (size_t i = 0; i < table->count; i++) {
        AddrEntry *entry = &table->entries[i];
        if (!entry->locked || entry->value_width == 0) continue;

        PlatformError err = memory_write(table->target, entry->address,
                                         entry->lock_value, entry->value_width);
        if (err != PLATFORM_OK) {
            entry->locked = false;   /* stop spinning */
            *had_error   = true;
            *error_index = i;
            return;
        }
    }
}

int addr_table_save(const AddrTable *table, const char *filepath)
{
    if (!table || !filepath) return 0;

    FILE *f = NULL;
    if (fopen_s(&f, filepath, "w") != 0 || !f) return 0;

    fprintf(f, "# MemForge Address Table v1\n");
    for (size_t i = 0; i < table->count; i++) {
        const AddrEntry *e = &table->entries[i];

        fprintf(f, "entry \"%s\" %s 0x%" PRIxPTR " %d",
                e->label, scanner_type_name(e->type), e->address, e->locked ? 1 : 0);

        if (e->locked && e->value_width > 0 && e->value_width <= ADDR_ENTRY_VALUE_MAX) {
            fputc(' ', f);
            for (unsigned short k = 0; k < e->value_width; k++) {
                fprintf(f, "%02X", e->lock_value[k]);
            }
        }
        fputc('\n', f);
    }

    int write_failed = fflush(f) != 0 || ferror(f);
    if (fclose(f) != 0 || write_failed) return 0;
    return 1;
}

int addr_table_load(AddrTable *table, const char *filepath)
{
    if (!table || !filepath) return 0;

    FILE *f = NULL;
    if (fopen_s(&f, filepath, "r") != 0 || !f) return 0;

    char line_buf[2048];

    /* Validate header */
    if (!fgets(line_buf, (int)sizeof(line_buf), f)) {
        fclose(f);
        return 0;
    }
    line_buf[strcspn(line_buf, "\r\n")] = '\0';

    if (strcmp(line_buf, "# MemForge Address Table v1") != 0) {
        fclose(f);
        return 0;   /* wrong format - fail loud, don't silently load nothing */
    }

    /* Read entries into a temporary list; commit only if all entries parse. */
    AddrTable temp;
    addr_table_init(&temp, table->target);

    while (fgets(line_buf, (int)sizeof(line_buf), f)) {
        if (!strchr(line_buf, '\n') && !feof(f)) { addr_table_destroy(&temp); fclose(f); return 0; }
        line_buf[strcspn(line_buf, "\r\n")] = '\0';
        if (line_buf[0] == '\0' || line_buf[0] == '#') continue;

        const char *p = line_buf;

        if (strncmp(p, "entry ", 6) != 0) {
            addr_table_destroy(&temp);
            fclose(f);
            return 0;
        }
        p += 6;

        /* Parse quoted label */
        while (*p == ' ') p++;
        if (*p != '"') { addr_table_destroy(&temp); fclose(f); return 0; }
        p++;
        char label[ADDR_ENTRY_LABEL_MAX];
        size_t label_len = 0;
        while (*p && *p != '"' && label_len < ADDR_ENTRY_LABEL_MAX - 1) {
            label[label_len++] = *p++;
        }
        label[label_len] = '\0';
        if (*p != '"' || label_len == 0) { addr_table_destroy(&temp); fclose(f); return 0; }
        p++;

        /* Parse type name */
        while (*p == ' ') p++;
        char type_name[16];
        size_t tn = 0;
        while (*p && *p != ' ' && tn < sizeof(type_name) - 1) type_name[tn++] = *p++;
        type_name[tn] = '\0';
        if (tn == 0) { addr_table_destroy(&temp); fclose(f); return 0; }
        p++;

        /* Parse address */
        while (*p == ' ') p++;
        uintptr_t address = 0;
        {
            const char *addr_start = p;
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
            while (*p && *p != ' ') p++;
            char addr_copy[32];
            size_t addr_len = (size_t)(p - addr_start);
            if (addr_len >= sizeof(addr_copy)) { addr_table_destroy(&temp); fclose(f); return 0; }
            memcpy(addr_copy, addr_start, addr_len);
            addr_copy[addr_len] = '\0';
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(addr_copy, &end, 16);
            if (errno == ERANGE || !end || *end != '\0' || parsed == 0 ||
                parsed > (unsigned long long)UINTPTR_MAX) {
                addr_table_destroy(&temp); fclose(f); return 0;
            }
            address = (uintptr_t)parsed;
        }

        /* Parse locked flag */
        while (*p == ' ') p++;
        int locked_flag = 0;
        if (*p == '0') locked_flag = 0;
        else if (*p == '1') locked_flag = 1;
        else { addr_table_destroy(&temp); fclose(f); return 0; }
        p++;
        if (*p != ' ' && *p != '\0') { addr_table_destroy(&temp); fclose(f); return 0; }

        ScanType type;
        if (scanner_type_from_name(type_name, &type) != PLATFORM_OK) {
            addr_table_destroy(&temp);
            fclose(f);
            return 0;
        }

        int idx = addr_table_add(&temp, label, type, address);
        if (idx < 0) { addr_table_destroy(&temp); fclose(f); return 0; }

        if (locked_flag) {
            /* Parse lock value hex bytes */
            while (*p == ' ') p++;
            unsigned short width = temp.entries[idx].value_width;
            if (width == 0 || width > ADDR_ENTRY_VALUE_MAX) {
                addr_table_destroy(&temp);
                fclose(f);
                return 0;
            }
            unsigned char lock_bytes[ADDR_ENTRY_VALUE_MAX];
            for (unsigned short k = 0; k < width; k++) {
                if (!p[0] || !p[1]) {
                    addr_table_destroy(&temp);
                    fclose(f);
                    return 0;
                }
                int byte_val = parse_hex_byte(p);
                if (byte_val < 0) {
                    addr_table_destroy(&temp);
                    fclose(f);
                    return 0;
                }
                lock_bytes[k] = (unsigned char)byte_val;
                p += 2;
            }
            while (*p == ' ') p++;
            if (*p != '\0') {
                addr_table_destroy(&temp);
                fclose(f);
                return 0;
            }
            /* Persisted locks are validated but intentionally loaded inert. */
        } else {
            while (*p == ' ') p++;
            if (*p != '\0') {
                addr_table_destroy(&temp);
                fclose(f);
                return 0;
            }
        }
    }
    if (ferror(f) || fclose(f) != 0) { addr_table_destroy(&temp); return 0; }

    /* Commit: replace existing entries. */
    addr_table_destroy(table);
    *table = temp;

    return 1;
}
