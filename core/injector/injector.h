#ifndef INJECTOR_H
#define INJECTOR_H

#include "core/process/process.h"
#include "platform/injector.h"

typedef PlatformInjection Injection;

InjectionError injector_start(const Target *target, const wchar_t *path, Injection **out);
InjectionError injector_poll(Injection *injection, int *complete, unsigned long long *module_base);
InjectionError injector_release(Injection **injection);
const char *injector_error_string(InjectionError error);

#endif
