#ifndef PROCESS_H
#define PROCESS_H

#include <stddef.h>
#include "platform/platform.h"

#define PROCESS_NAME_MAX PLATFORM_NAME_MAX

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

void          process_target_init(Target *target);
/* target must have been initialized and must not already own a process handle. */
PlatformError process_attach(unsigned int pid, Target *target);
void          process_detach(Target *target);
PlatformError process_is_alive(const Target *target, int *alive);

PlatformError process_enable_privilege(void);

const char   *process_error_string(PlatformError err);

#endif
