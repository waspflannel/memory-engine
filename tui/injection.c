#include "tui_internal.h"
#include "core/injector/injector.h"
#include <stdio.h>
#include <stdlib.h>

static Injection *injection;

static void show_error(InjectionError error);

void tui_injection_start(const wchar_t *path)
{
    if (!tui_state.attached) { tui_set_status(L"No process attached", TRUE); return; }
    if (injection) { tui_set_status(L"DLL loading or cleanup already pending", TRUE); return; }
    if (tui_state.debugger) { tui_set_status(L"Stop watching before loading a DLL", TRUE); return; }
    InjectionError error = injector_start(&tui_state.target, path, &injection);
    if (error != INJECTION_OK) show_error(error);
    else tui_set_status(L"Loading DLL...", FALSE);
}

void tui_injection_poll(void)
{
    if (!injection) return;
    int complete = 0;
    unsigned long long base = 0;
    InjectionError error = injector_poll(injection, &complete, &base);
    if (!complete && error == INJECTION_OK) return;
    InjectionError cleanup = injector_release(&injection);
    if (cleanup != INJECTION_OK) { show_error(cleanup); return; }
    if (error != INJECTION_OK) { show_error(error); return; }
    wchar_t message[96];
    swprintf_s(message, _countof(message), L"DLL loaded at %016llX; remains loaded after detach", base);
    tui_set_status(message, FALSE);
}

int tui_injection_is_running(void)
{
    return injection != NULL;
}

int tui_injection_release(void)
{
    InjectionError error = injector_release(&injection);
    if (error == INJECTION_OK) return 1;
    show_error(error);
    return 0;
}

static void show_error(InjectionError error)
{
    wchar_t message[STATUS_MSG_MAX];
    swprintf_s(message, _countof(message), L"DLL: %S", injector_error_string(error));
    tui_set_status(message, TRUE);
}
