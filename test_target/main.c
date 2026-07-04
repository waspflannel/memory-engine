#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>

static volatile int     g_health  = 100;
static volatile float   g_speed   = 1.5f;
static volatile double  g_gravity = 9.81;
static volatile wchar_t g_name[]  = L"TestTarget";
static volatile int     g_ammo    = 30;

int main(void)
{
    DWORD pid = GetCurrentProcessId();

    wprintf(L"=== MemForge Test Target ===\n");
    wprintf(L"PID: %u\n", pid);
    wprintf(L"\n");
    wprintf(L"Known values (use these addresses to verify reads/writes):\n");
    wprintf(L"  g_health  (i32)  @ 0x%p  = %d\n", (void *)&g_health, g_health);
    wprintf(L"  g_speed   (f32)  @ 0x%p  = %.1f\n", (void *)&g_speed, g_speed);
    wprintf(L"  g_gravity (f64)  @ 0x%p  = %.2f\n", (void *)&g_gravity, g_gravity);
    wprintf(L"  g_ammo    (i32)  @ 0x%p  = %d\n", (void *)&g_ammo, g_ammo);
    wprintf(L"  g_name    (str)  @ 0x%p  = %s\n", (void *)&g_name, g_name);
    wprintf(L"\n");
    wprintf(L"Commands (press key, then Enter):\n");
    wprintf(L"  h = toggle health (100 <-> 50)\n");
    wprintf(L"  a = decrement ammo by 1\n");
    wprintf(L"  s = change speed (+0.5)\n");
    wprintf(L"  g = change gravity (*2)\n");
    wprintf(L"  v = print all current values\n");
    wprintf(L"  q = quit\n");
    wprintf(L"\n");
    fflush(stdout);

    for (;;) {
        wprintf(L"> ");
        int c = getwchar();
        if (c == WEOF) break;

        while (getwchar() != L'\n' && !feof(stdin)) {}

        switch (c) {
        case L'h':
        case L'H':
            g_health = (g_health == 100) ? 50 : 100;
            wprintf(L"  g_health = %d\n", g_health);
            break;
        case L'a':
        case L'A':
            g_ammo--;
            wprintf(L"  g_ammo = %d\n", g_ammo);
            break;
        case L's':
        case L'S':
            g_speed += 0.5f;
            wprintf(L"  g_speed = %.1f\n", g_speed);
            break;
        case L'g':
        case L'G':
            g_gravity *= 2.0;
            wprintf(L"  g_gravity = %.2f\n", g_gravity);
            break;
        case L'v':
        case L'V':
            wprintf(L"  g_health  = %d\n", g_health);
            wprintf(L"  g_speed   = %.1f\n", g_speed);
            wprintf(L"  g_gravity = %.2f\n", g_gravity);
            wprintf(L"  g_ammo    = %d\n", g_ammo);
            wprintf(L"  g_name    = %s\n", g_name);
            break;
        case L'q':
        case L'Q':
            wprintf(L"Goodbye.\n");
            return 0;
        default:
            wprintf(L"  Unknown command\n");
            break;
        }
        fflush(stdout);
    }

    return 0;
}
