#include "core/injector/injector.h"

InjectionError injector_start(const Target *target, const wchar_t *path, Injection **out)
{
    if (!target || !target->handle) return INJECTION_ERR_INVALID;
    return platform_inject_start(target->pid, path, out);
}

InjectionError injector_poll(Injection *injection, int *complete, unsigned long long *module_base)
{
    return platform_inject_poll(injection, complete, module_base);
}

InjectionError injector_release(Injection **injection)
{
    return platform_inject_release(injection);
}

const char *injector_error_string(InjectionError error)
{
    return platform_inject_error_string(error);
}
