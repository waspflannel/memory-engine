#ifndef PLATFORM_INJECTOR_H
#define PLATFORM_INJECTOR_H

#include <stddef.h>

typedef enum {
    INJECTION_OK = 0, INJECTION_ERR_INVALID, INJECTION_ERR_PATH,
    INJECTION_ERR_NOT_DLL, INJECTION_ERR_ARCHITECTURE, INJECTION_ERR_ACCESS,
    INJECTION_ERR_MODULES, INJECTION_ERR_MEMORY, INJECTION_ERR_WRITE,
    INJECTION_ERR_THREAD, INJECTION_ERR_WAIT, INJECTION_ERR_LOAD,
    INJECTION_ERR_BUSY, INJECTION_ERR_CLEANUP
} InjectionError;

typedef struct PlatformInjection PlatformInjection;

/* Native x64 standard loader only. out must initially be NULL. */
InjectionError platform_inject_start(unsigned int pid, const wchar_t *path, PlatformInjection **out);
/* Nonblocking. A completed operation still needs release, including failed loads. */
InjectionError platform_inject_poll(PlatformInjection *injection, int *complete, unsigned long long *module_base);
/* BUSY retains ownership: never free the remote argument while its thread runs. */
InjectionError platform_inject_release(PlatformInjection **injection);
const char *platform_inject_error_string(InjectionError error);

#endif
