#ifndef PROCESS_H
#define PROCESS_H

#include <stddef.h>
#include "platform/platform.h"

#define PROC_NAME_MAX 260

typedef struct {
    unsigned int pid;
    wchar_t      name[PROC_NAME_MAX];
} ProcessEntry;

typedef struct {
    unsigned int       pid;
    void              *handle;
    unsigned long long base;
    size_t             base_size;
    wchar_t            name[PROC_NAME_MAX];
} Target;

PlatError   proc_enumerate(ProcessEntry **entries, unsigned int *count);
void        proc_free_list(ProcessEntry *entries);

PlatError   proc_attach(unsigned int pid, Target *target);
void        proc_detach(Target *target);

PlatError   proc_enable_privilege(void);

int         proc_last_error(void);
const char *proc_last_error_string(void);

#endif
