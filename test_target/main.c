#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>

static volatile int     target_health  = 100;
static volatile float   target_speed   = 1.5f;
static volatile double  target_gravity = 9.81;
static volatile wchar_t target_name[]  = L"TestTarget";
static volatile int     target_ammo    = 30;
static volatile unsigned int target_counter_u32 = 4294967295u;  /* for u32 scan */
static volatile long long    target_counter_i64 = 0x123456789ABCll;  /* for i64 scan */
static volatile char        target_ascii_string[] = "MemForgeASCII";  /* for string ASCII scan */

int main(void)
{
    DWORD pid = GetCurrentProcessId();

    wprintf(L"=== MemForge Test Target ===\n");
    wprintf(L"PID: %u\n", pid);
    wprintf(L"\n");
    wprintf(L"Known values (use these addresses to verify reads/writes):\n");
    wprintf(L"  target_health  (i32)  @ 0x%p  = %d\n", (void *)&target_health, target_health);
    wprintf(L"  target_speed   (f32)  @ 0x%p  = %.1f\n", (void *)&target_speed, target_speed);
    wprintf(L"  target_gravity (f64)  @ 0x%p  = %.2f\n", (void *)&target_gravity, target_gravity);
    wprintf(L"  target_ammo    (i32)  @ 0x%p  = %d\n", (void *)&target_ammo, target_ammo);
    wprintf(L"  target_name    (str)  @ 0x%p  = %s\n", (void *)&target_name, target_name);
    wprintf(L"  target_counter_u32 (u32) @ 0x%p = %u\n", (void *)&target_counter_u32, target_counter_u32);
    wprintf(L"  target_counter_i64 (i64) @ 0x%p = 0x%llx\n", (void *)&target_counter_i64, target_counter_i64);
    wprintf(L"  target_ascii_string (str/ascii) @ 0x%p = MemForgeASCII\n", (void *)&target_ascii_string);
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
            target_health = (target_health == 100) ? 50 : 100;
            wprintf(L"  target_health = %d\n", target_health);
            break;
        case L'a':
        case L'A':
            target_ammo--;
            wprintf(L"  target_ammo = %d\n", target_ammo);
            break;
        case L's':
        case L'S':
            target_speed += 0.5f;
            wprintf(L"  target_speed = %.1f\n", target_speed);
            break;
        case L'g':
        case L'G':
            target_gravity *= 2.0;
            wprintf(L"  target_gravity = %.2f\n", target_gravity);
            break;
        case L'v':
        case L'V':
            wprintf(L"  target_health  = %d\n", target_health);
            wprintf(L"  target_speed   = %.1f\n", target_speed);
            wprintf(L"  target_gravity = %.2f\n", target_gravity);
            wprintf(L"  target_ammo    = %d\n", target_ammo);
            wprintf(L"  target_name    = %s\n", target_name);
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
