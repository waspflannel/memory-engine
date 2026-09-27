#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

__declspec(align(8)) static unsigned char *volatile root_three;
__declspec(align(8)) static unsigned char *volatile root_two;
__declspec(align(8)) static unsigned char *volatile many_roots[600];

int main(void)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    unsigned char *first = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    unsigned char *second = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    unsigned char *leaf = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!first || !second || !leaf) return 1;
    root_three = first;
    root_two = second;
    memcpy(first + 24, &second, sizeof(second));
    memcpy(second + 32, &leaf, sizeof(leaf));
    int value = 12345;
    memcpy(leaf + 40, &value, sizeof(value));
    printf("%llX %llX %llX\n", (unsigned long long)&root_three,
           (unsigned long long)&root_two, (unsigned long long)(leaf + 40));
    fflush(stdout);
    for (;;) {
        int command = getchar();
        if (command == EOF || command == 'q') break;
        DWORD previous;
        if (command == 'x' && !VirtualProtect(second, 4096, PAGE_NOACCESS, &previous)) return 2;
        if (command == 'r' && !VirtualProtect(second, 4096, PAGE_READWRITE, &previous)) return 3;
        if (command == 'c') {
            for (size_t i = 0; i < sizeof(many_roots) / sizeof(many_roots[0]); i++) many_roots[i] = leaf;
        }
        printf("ok\n");
        fflush(stdout);
    }
    VirtualFree(first, 0, MEM_RELEASE);
    VirtualFree(second, 0, MEM_RELEASE);
    VirtualFree(leaf, 0, MEM_RELEASE);
    return 0;
}
