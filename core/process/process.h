#ifndef PROCESS_H
#define PROCESS_H

#include <stddef.h>
#include "platform/platform.h"

#define PROCESS_NAME_MAX 260

typedef struct {
    unsigned int pid;
    wchar_t      name[PROCESS_NAME_MAX];
} ProcessEntry;

typedef struct {
    unsigned int       pid;
    void              *handle;
    unsigned long long base;
    size_t             base_size;
    wchar_t            name[PROCESS_NAME_MAX];
} Target;

PlatformError process_list(ProcessEntry **entries, unsigned int *count);
void          process_free_list(ProcessEntry *entries);

PlatformError process_attach(unsigned int pid, Target *target);
void          process_detach(Target *target);

PlatformError process_enable_privilege(void);

int           process_last_os_error(void);
const char   *process_error_string(PlatformError err);
const char   *process_last_error_string(void);

#endif
