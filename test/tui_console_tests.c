#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define SCREEN_WIDTH 80
#define SCREEN_HEIGHT 25

static volatile LONG fixture[32] = { 19088743 };
static HANDLE console_input;
static HANDLE console_output;
static HANDLE application;
static wchar_t snapshot[(SCREEN_WIDTH + 1) * SCREEN_HEIGHT + 1];

static int run_driver(const wchar_t *executable);
static int send_key(WORD key, wchar_t character);
static int send_command(const wchar_t *command);
static int wait_for_text(const wchar_t *text);
static int read_screen(void);
static void print_screen(void);

/* Isolate console attachment in a helper process: the caller's console and
   redirected standard handles remain untouched. The job owns both children. */
int wmain(int argc, wchar_t **argv)
{
    if (argc == 3 && wcscmp(argv[1], L"--driver") == 0) return run_driver(argv[2]);
    if (argc != 2) {
        fprintf(stderr, "usage: tui_console_tests <memforge.exe>\n");
        return 1;
    }

    wchar_t self[MAX_PATH];
    wchar_t command[MAX_PATH * 2 + 32];
    if (!GetModuleFileNameW(NULL, self, _countof(self))) return 1;
    if (swprintf_s(command, _countof(command), L"\"%s\" --driver \"%s\"", self, argv[1]) < 0) return 1;
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        if (job) CloseHandle(job);
        return 1;
    }

    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION child = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    SECURITY_ATTRIBUTES security = { sizeof(security), NULL, TRUE };
    startup.hStdInput = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  &security, OPEN_EXISTING, 0, NULL);
    HANDLE current = GetCurrentProcess();
    int handles_ready = startup.hStdInput != INVALID_HANDLE_VALUE &&
        DuplicateHandle(current, GetStdHandle(STD_OUTPUT_HANDLE), current, &startup.hStdOutput,
                        0, TRUE, DUPLICATE_SAME_ACCESS) &&
        DuplicateHandle(current, GetStdHandle(STD_ERROR_HANDLE), current, &startup.hStdError,
                        0, TRUE, DUPLICATE_SAME_ACCESS);
    int started = handles_ready && CreateProcessW(self, command, NULL, NULL, TRUE,
                            CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &startup, &child);
    if (startup.hStdInput != INVALID_HANDLE_VALUE) CloseHandle(startup.hStdInput);
    if (startup.hStdOutput) CloseHandle(startup.hStdOutput);
    if (startup.hStdError) CloseHandle(startup.hStdError);
    DWORD result = 1;
    if (started) {
        if (AssignProcessToJobObject(job, child.hProcess) && ResumeThread(child.hThread) != (DWORD)-1) {
            if (WaitForSingleObject(child.hProcess, 30000) == WAIT_OBJECT_0)
                GetExitCodeProcess(child.hProcess, &result);
            else fprintf(stderr, "Console integration test timed out\n");
        }
        /* Also covers a failure before assignment to the cleanup job. */
        if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) TerminateProcess(child.hProcess, 1);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
    } else fprintf(stderr, "Cannot launch console test helper: %lu\n", GetLastError());
    CloseHandle(job);
    return (int)result;
}

static int run_driver(const wchar_t *executable)
{
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION child = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    if (!CreateProcessW(executable, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                        NULL, NULL, &startup, &child)) {
        fprintf(stderr, "Cannot launch MemForge: %lu\n", GetLastError());
        return 1;
    }
    application = child.hProcess;
    CloseHandle(child.hThread);
    int passed = 0;
    const char *step = "attach to hidden console";
    FreeConsole();
    ULONGLONG deadline = GetTickCount64() + 5000;
    while (!AttachConsole(child.dwProcessId)) {
        if (GetTickCount64() >= deadline || WaitForSingleObject(application, 0) == WAIT_OBJECT_0) goto cleanup;
        Sleep(20);
    }
    console_input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    console_output = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    step = "configure 80 by 25 console";
    SMALL_RECT small = {0, 0, 39, 9};
    SMALL_RECT window = {0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1};
    COORD size = {SCREEN_WIDTH, SCREEN_HEIGHT};
    if (console_input == INVALID_HANDLE_VALUE || console_output == INVALID_HANDLE_VALUE ||
        !SetConsoleWindowInfo(console_output, TRUE, &small) ||
        !SetConsoleScreenBufferSize(console_output, size) ||
        !SetConsoleWindowInfo(console_output, TRUE, &window)) goto cleanup;

    step = "initial application rendering";
    if (!wait_for_text(L"MemForge")) goto cleanup;
    step = "detached read error";
    if (!send_command(L"read 0 4") || !wait_for_text(L" No process attached")) goto cleanup;
    wchar_t command[128];
    swprintf_s(command, _countof(command), L"attach %lu", GetCurrentProcessId());
    step = "attach to test fixture";
    if (!send_command(command) || !wait_for_text(L"Attached to")) goto cleanup;
    step = "scan fixture value";
    if (!send_command(L"scan 19088743") || !wait_for_text(L"First scan:")) goto cleanup;
    if (wcsstr(snapshot, L"First scan: 0 hits")) goto cleanup;
    swprintf_s(command, _countof(command), L"addentry %llX i32 console_fixture",
               (unsigned long long)(uintptr_t)fixture);
    step = "save scan address";
    if (!send_command(command) || !wait_for_text(L"Added entry 0:")) goto cleanup;
    step = "lock saved address";
    if (!send_command(L"lockentry 0 19088743") || !wait_for_text(L"Entry 0 locked")) goto cleanup;
    fixture[0] = 0;
    deadline = GetTickCount64() + 2000;
    while (fixture[0] != 19088743 && GetTickCount64() < deadline) Sleep(10);
    if (fixture[0] != 19088743) goto cleanup;
    swprintf_s(command, _countof(command), L"read %llX 128", (unsigned long long)(uintptr_t)fixture);
    step = "long read opens rendered Hex View";
    if (!send_command(command) || !wait_for_text(L"Read succeeded;") ||
        !wcsstr(snapshot, L"Hex View  0x") || !wcsstr(snapshot, L"67 45 23 01")) goto cleanup;
    printf("Rendered 80x25 screen after attach, scan, save, lock, and 128-byte read:\n");
    print_screen();
    step = "invalid command error";
    if (!send_command(L"invalid_fixture_command") || !wait_for_text(L"Unknown command:")) goto cleanup;
    step = "cleared command stays empty after status expires";
    if (!wait_for_text(L" > ") || wcsstr(snapshot, L"invalid_fixture_command")) goto cleanup;
    step = "quit through keyboard";
    if (!send_command(L"quit") || WaitForSingleObject(application, 5000) != WAIT_OBJECT_0) goto cleanup;
    DWORD exit_code;
    if (!GetExitCodeProcess(application, &exit_code) || exit_code != 0) goto cleanup;
    passed = 1;

cleanup:
    if (!passed) {
        fprintf(stderr, "FAIL: %s (Win32 %lu)\n", step, GetLastError());
        if (console_output && console_output != INVALID_HANDLE_VALUE && read_screen()) print_screen();
    }
    if (WaitForSingleObject(application, 0) != WAIT_OBJECT_0) {
        TerminateProcess(application, 1);
        WaitForSingleObject(application, 5000);
    }
    if (console_input && console_input != INVALID_HANDLE_VALUE) CloseHandle(console_input);
    if (console_output && console_output != INVALID_HANDLE_VALUE) CloseHandle(console_output);
    FreeConsole();
    CloseHandle(application);
    printf("Console integration: %s\n", passed ? "passed" : "failed");
    return passed ? 0 : 1;
}

static int send_key(WORD key, wchar_t character)
{
    INPUT_RECORD records[2] = {0};
    records[0].EventType = KEY_EVENT;
    records[0].Event.KeyEvent.bKeyDown = TRUE;
    records[0].Event.KeyEvent.wRepeatCount = 1;
    records[0].Event.KeyEvent.wVirtualKeyCode = key;
    records[0].Event.KeyEvent.uChar.UnicodeChar = character;
    records[1] = records[0];
    records[1].Event.KeyEvent.bKeyDown = FALSE;
    DWORD written;
    return WriteConsoleInputW(console_input, records, 2, &written) && written == 2;
}

static int send_command(const wchar_t *command)
{
    /* Escape returns either the panel or command focus to the sidebar. */
    if (!send_key(VK_ESCAPE, 0) || !send_key(VK_TAB, 0) || !send_key(VK_TAB, 0)) return 0;
    for (const wchar_t *text = command; *text; text++) {
        if (!send_key(0, *text)) return 0;
    }
    return send_key(VK_RETURN, 0);
}

static int wait_for_text(const wchar_t *text)
{
    ULONGLONG deadline = GetTickCount64() + 10000;
    do {
        if (read_screen() && wcsstr(snapshot, text)) return 1;
        if (WaitForSingleObject(application, 0) == WAIT_OBJECT_0) return 0;
        Sleep(20);
    } while (GetTickCount64() < deadline);
    return 0;
}

static int read_screen(void)
{
    for (SHORT row = 0; row < SCREEN_HEIGHT; row++) {
        COORD origin = {0, row};
        DWORD read;
        wchar_t *line = snapshot + row * (SCREEN_WIDTH + 1);
        if (!ReadConsoleOutputCharacterW(console_output, line, SCREEN_WIDTH, origin, &read) ||
            read != SCREEN_WIDTH) return 0;
        line[SCREEN_WIDTH] = L'\n';
    }
    snapshot[_countof(snapshot) - 1] = L'\0';
    return 1;
}

static void print_screen(void)
{
    /* ASCII keeps captured evidence readable regardless of the runner code page. */
    for (const wchar_t *text = snapshot; *text; text++)
        putchar(*text == L'\n' || (*text >= L' ' && *text <= L'~') ? (int)*text : '|');
    fflush(stdout);
}
