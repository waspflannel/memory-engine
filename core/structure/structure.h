#ifndef STRUCTURE_H
#define STRUCTURE_H

#include "core/scanner/scanner.h"

#define STRUCTURE_MAX_BYTES 256
#define STRUCTURE_MAX_FIELDS 32
#define STRUCTURE_LABEL_MAX 64

typedef struct {
    size_t offset;
    ScanType type;
    wchar_t label[STRUCTURE_LABEL_MAX];
} StructureField;

typedef struct {
    unsigned long long address;
    size_t size, field_count;
    unsigned char bytes[STRUCTURE_MAX_BYTES];
    unsigned char readable[STRUCTURE_MAX_BYTES];
    unsigned char changed[STRUCTURE_MAX_BYTES];
    StructureField fields[STRUCTURE_MAX_FIELDS];
} StructureWindow;

typedef enum { STRUCTURE_FIELD_OK, STRUCTURE_FIELD_INVALID, STRUCTURE_FIELD_FULL } StructureFieldError;

/* Invalid open leaves the previous window intact. A valid open clears labels;
   partial reads retain only known current bytes and return PARTIAL_READ. */
PlatformError structure_open(StructureWindow *window, const Target *target,
                             unsigned long long address, size_t size);
PlatformError structure_refresh(StructureWindow *window, const Target *target);
/* Setting the same offset replaces its field, including at capacity. */
StructureFieldError structure_set_field(StructureWindow *window, size_t offset,
                                        ScanType type, const wchar_t *label);

#endif
