#ifndef ADDRESS_TABLE_H
#define ADDRESS_TABLE_H

#include <stddef.h>
#include <stdbool.h>
#include "core/scanner/scanner.h"
#include "core/memory/memory.h"

#define ADDR_ENTRY_LABEL_MAX 64
#define ADDR_ENTRY_VALUE_MAX 256
#define ADDR_TABLE_LOCK_INTERVAL_MS  50
#define ADDR_TABLE_REFRESH_INTERVAL_MS 200

typedef struct {
    char           label[ADDR_ENTRY_LABEL_MAX];
    ScanType       type;
    uintptr_t      address;
    bool           locked;
    unsigned char  current_value[ADDR_ENTRY_VALUE_MAX];
    unsigned char  lock_value[ADDR_ENTRY_VALUE_MAX];
    bool           value_valid;
    unsigned short value_width;
} AddrEntry;

typedef struct {
    const Target *target;
    AddrEntry    *entries;
    size_t        count;
    size_t        capacity;
} AddrTable;

typedef enum {
    ADDR_TABLE_IO_OK = 0,
    ADDR_TABLE_IO_INVALID_PARAM,
    ADDR_TABLE_IO_OPEN_FAILED,
    ADDR_TABLE_IO_MALFORMED,
    ADDR_TABLE_IO_READ_FAILED,
    ADDR_TABLE_IO_WRITE_FAILED,
    ADDR_TABLE_IO_OUT_OF_MEMORY,
} AddrTableIoError;

int  addr_table_init(AddrTable *table, const Target *target);
void addr_table_destroy(AddrTable *table);
void addr_table_set_target(AddrTable *table, const Target *target);

int  addr_table_add(AddrTable *table, const char *label, ScanType type, uintptr_t address);
int  addr_table_remove(AddrTable *table, size_t index);
int  addr_table_rename(AddrTable *table, size_t index, const char *label);
int  addr_table_lock(AddrTable *table, size_t index, const void *lock_value);
int  addr_table_unlock(AddrTable *table, size_t index);

/*
 * addr_table_refresh: read current value for every entry.  Entries whose
 * read fails get value_valid = false.  Call this at ADDR_TABLE_REFRESH_INTERVAL_MS.
 */
PlatformError addr_table_refresh(AddrTable *table);

/*
 * addr_table_lock_write: for each locked entry, write its lock_value back.
 * On a write failure, sets *had_error = true (caller must provide non-NULL)
 * and stores the failing index in *error_index, then unlocks the entry so it
 * does not spin on a dead target.
 */
void addr_table_lock_write(AddrTable *table, bool *had_error, size_t *error_index);

/*
 * addr_table_save / addr_table_load: simple line-based format.
 * addr_table_load validates the file at the boundary; malformed lines are a
 * loud failure (return 0) that leaves the table unmodified.
 */
AddrTableIoError addr_table_save(const AddrTable *table, const wchar_t *filepath);
AddrTableIoError addr_table_load(AddrTable *table, const wchar_t *filepath);
const char      *addr_table_io_error_string(AddrTableIoError error);

#endif
