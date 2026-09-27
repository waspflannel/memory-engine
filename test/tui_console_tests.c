#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define SCREEN_WIDTH 80
#define SCREEN_HEIGHT 25

static volatile LONG fixture[32] = { 19088743 };
__declspec(align(8)) static volatile LONG *volatile fixture_pointer = fixture;
static HANDLE console_input;
static HANDLE console_output;
static HANDLE application;
static HANDLE debug_target;
static HANDLE debug_input;
static wchar_t snapshot[(SCREEN_WIDTH + 1) * SCREEN_HEIGHT + 1];

static int run_driver(const wchar_t *executable);
static int send_key(WORD key, wchar_t character);
static int send_command(const wchar_t *command);
static int wait_for_text(const wchar_t *text);
static int read_screen(void);
static void print_screen(void);
static int start_debug_target(const wchar_t *application_path, DWORD *pid, unsigned int *thread_id,
                              unsigned long long *code_address, unsigned long long *value_address);

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
    wchar_t command[MAX_PATH + 32];
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
    step = "structure opens and accepts typed field";
    swprintf_s(command, _countof(command), L"structure %llX 128", (unsigned long long)(uintptr_t)fixture_pointer);
    if (!send_command(command) || !wait_for_text(L"Structure opened") ||
        !send_command(L"field 4 u32 score") || !wait_for_text(L"Structure field saved")) goto cleanup;
    fixture[1] = 42;
    if (!send_key(VK_ESCAPE, 0) || !send_key(VK_TAB, 0) || !send_key(0, L'r') ||
        !wait_for_text(L"score (u32): 42") || !wcsstr(snapshot, L"* +0004")) goto cleanup;
    printf("Rendered structure inspection after changing a labelled field:\n");
    print_screen();
    step = "pointer scan and resolve through static executable root";
    swprintf_s(command, _countof(command), L"pointers %llX 1 0", (unsigned long long)(uintptr_t)fixture);
    if (!send_command(command) || !wait_for_text(L"Pointers:") || wcsstr(snapshot, L"Pointers: 0 paths") ||
        !send_key(0, L'r') || !wait_for_text(L"Pointer resolved")) goto cleanup;
    printf("Rendered pointer path results:\n");
    print_screen();
    step = "pointer path and actions remain usable at 40 by 10";
    COORD narrow_size = {40, 10};
    if (!SetConsoleWindowInfo(console_output, TRUE, &small) ||
        !SetConsoleScreenBufferSize(console_output, narrow_size)) goto cleanup;
    for (int i = 0; i < 32; i++) if (!send_key(VK_RIGHT, 0)) goto cleanup;
    wchar_t destination[32];
    swprintf_s(destination, _countof(destination), L"%llX", (unsigned long long)(uintptr_t)fixture);
    if (!wait_for_text(destination) || !wcsstr(snapshot, L"[R] Resolve [Enter] Hex")) goto cleanup;
    printf("Rendered narrow pointer view after horizontal scrolling:\n");
    print_screen();
    if (!SetConsoleScreenBufferSize(console_output, size) ||
        !SetConsoleWindowInfo(console_output, TRUE, &window)) goto cleanup;
    step = "pointer scan cancellation preserves session paths across detach";
    if (!send_command(command) || !send_command(L"detach") || !wait_for_text(L"[No process attached]")) goto cleanup;
    swprintf_s(command, _countof(command), L"attach %lu", GetCurrentProcessId());
    if (!send_command(command) || !wait_for_text(L"Attached to") ||
        !send_key(VK_ESCAPE, 0) || !send_key(VK_TAB, 0) || !send_key(0, L'r') ||
        !wait_for_text(L"Pointer resolved")) goto cleanup;
    step = "standard DLL injection command completes";
    wchar_t dll[MAX_PATH];
    wcscpy_s(dll, _countof(dll), executable);
    wchar_t *filename = wcsrchr(dll, L'\\');
    if (!filename) filename = wcsrchr(dll, L'/');
    if (!filename) goto cleanup;
    wcscpy_s(filename + 1, _countof(dll) - (size_t)(filename + 1 - dll), L"injector_fixture.dll");
    swprintf_s(command, _countof(command), L"inject \"%s\"", dll);
    if (!send_command(command) || !wait_for_text(L"DLL loaded at")) goto cleanup;
    printf("Standard DLL injection command completed in the attached fixture.\n");
    step = "invalid command error";
    if (!send_command(L"invalid_fixture_command") || !wait_for_text(L"Unknown command:")) goto cleanup;
    step = "cleared command stays empty after status expires";
    if (!wait_for_text(L" > ") || wcsstr(snapshot, L"invalid_fixture_command")) goto cleanup;
    DWORD target_pid;
    unsigned int thread_id;
    unsigned long long code_address, value_address;
    step = "start independent debugger fixture";
    if (!start_debug_target(executable, &target_pid, &thread_id, &code_address, &value_address)) goto cleanup;
    swprintf_s(command, _countof(command), L"attach %lu", target_pid);
    step = "attach debugger fixture";
    if (!send_command(command) || !wait_for_text(L"Attached to")) goto cleanup;
    LONG initial_value = 19088743;
    SIZE_T transferred;
    DWORD written;
    if (!WriteProcessMemory(debug_target, (LPVOID)(uintptr_t)value_address, &initial_value,
                            sizeof(initial_value), &transferred) || transferred != sizeof(initial_value)) goto cleanup;
    step = "scan selected watched value";
    if (!send_command(L"scan 19088743") || !wait_for_text(L"First scan:")) goto cleanup;
    /* Select Scanner from the sidebar, then k watches its selected result. */
    if (!send_key(VK_ESCAPE, 0)) goto cleanup;
    for (int i = 0; i < 8; i++) if (!send_key(VK_UP, 0)) goto cleanup;
    if (!send_key(VK_DOWN, 0) || !send_key(VK_RETURN, 0) || !send_key(0, L'k') ||
        !wait_for_text(L"Watching for changes")) goto cleanup;
    step = "CPU write pauses with old/new values and next instruction";
    if (!WriteFile(debug_input, "i", 1, &written, NULL) || written != 1 ||
        !wait_for_text(L"After: 19088744") || !wcsstr(snapshot, L"Before: 19088743") ||
        !wcsstr(snapshot, L"Next instructions (after write)") ||
        !wcsstr(snapshot, L"[C] Continue") || !wcsstr(snapshot, L"[S] Stop watching") ||
        !wcsstr(snapshot, L"[D] Detach")) goto cleanup;
    wchar_t next_instruction[32];
    swprintf_s(next_instruction, _countof(next_instruction), L"%016llX", code_address + 2);
    if (!wcsstr(snapshot, next_instruction)) goto cleanup;
    printf("Rendered watched-value change screen:\n");
    print_screen();
    step = "continue action watches next change";
    if (!send_key(0, L'c') || !wait_for_text(L"Watching for changes") ||
        !WriteFile(debug_input, "i", 1, &written, NULL) || written != 1 ||
        !wait_for_text(L"After: 19088745") || !wcsstr(snapshot, L"Before: 19088744")) goto cleanup;
    step = "stop watching keeps memory target attached";
    if (!send_key(0, L's') || !wait_for_text(L"Stopped watching; target remains attached") ||
        WaitForSingleObject(debug_target, 0) != WAIT_TIMEOUT) goto cleanup;
    swprintf_s(command, _countof(command), L"read %llX 4", value_address);
    if (!send_command(command) || !wait_for_text(L"69 45 23 01")) goto cleanup;
    swprintf_s(command, _countof(command), L"addentry %llX i32 watch_fixture", value_address);
    step = "address-table selected watch shortcut";
    if (!send_command(command) || !wait_for_text(L"Added entry 1:")) goto cleanup;
    /* addentry selects the new row; open AddrTable from the sidebar. */
    if (!send_key(VK_ESCAPE, 0)) goto cleanup;
    for (int i = 0; i < 8; i++) if (!send_key(VK_UP, 0)) goto cleanup;
    if (!send_key(VK_DOWN, 0) || !send_key(VK_DOWN, 0) || !send_key(VK_RETURN, 0) || !send_key(0, L'k') ||
        !wait_for_text(L"Watching for changes")) goto cleanup;
    if (!WriteFile(debug_input, "i", 1, &written, NULL) || written != 1 ||
        !wait_for_text(L"After: 19088746")) goto cleanup;
    step = "detach action releases debugger and memory target";
    if (!send_key(0, L'd') || !wait_for_text(L"[No process attached]") ||
        WaitForSingleObject(debug_target, 0) != WAIT_TIMEOUT) goto cleanup;
    step = "watch command and quit while active";
    swprintf_s(command, _countof(command), L"attach %lu", target_pid);
    if (!send_command(command) || !wait_for_text(L"Attached to")) goto cleanup;
    swprintf_s(command, _countof(command), L"watch %llX i32", value_address);
    if (!send_command(command) || !wait_for_text(L"Watching for changes")) goto cleanup;
    step = "quit through keyboard";
    if (!send_command(L"quit") || WaitForSingleObject(application, 5000) != WAIT_OBJECT_0) goto cleanup;
    DWORD exit_code;
    if (!GetExitCodeProcess(application, &exit_code) || exit_code != 0) goto cleanup;
    if (WaitForSingleObject(debug_target, 0) != WAIT_TIMEOUT) goto cleanup;
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
    if (debug_input) CloseHandle(debug_input);
    if (debug_target) {
        if (WaitForSingleObject(debug_target, 2000) != WAIT_OBJECT_0) TerminateProcess(debug_target, 1);
        CloseHandle(debug_target);
    }
    if (console_input && console_input != INVALID_HANDLE_VALUE) CloseHandle(console_input);
    if (console_output && console_output != INVALID_HANDLE_VALUE) CloseHandle(console_output);
    FreeConsole();
    CloseHandle(application);
    printf("Console integration: %s\n", passed ? "passed" : "failed");
    return passed ? 0 : 1;
}

static int start_debug_target(const wchar_t *application_path, DWORD *pid, unsigned int *thread_id,
                              unsigned long long *code_address, unsigned long long *value_address)
{
    wchar_t path[MAX_PATH];
    if (wcsncpy_s(path, _countof(path), application_path, _TRUNCATE) != 0) return 0;
    wchar_t *filename = wcsrchr(path, L'\\');
    if (!filename) filename = wcsrchr(path, L'/');
    filename = filename ? filename + 1 : path;
    if (wcscpy_s(filename, _countof(path) - (size_t)(filename - path), L"debugger_target.exe") != 0) return 0;
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    HANDLE input_read = NULL, output_read = NULL, output_write = NULL;
    int started = 0;
    if (!CreatePipe(&input_read, &debug_input, &security, 0) ||
        !CreatePipe(&output_read, &output_write, &security, 0) ||
        !SetHandleInformation(debug_input, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0)) goto done;
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION child = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input_read;
    startup.hStdOutput = output_write;
    startup.hStdError = output_write;
    if (!CreateProcessW(path, NULL, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) goto done;
    debug_target = child.hProcess;
    *pid = child.dwProcessId;
    CloseHandle(child.hThread);
    char info[128];
    DWORD count;
    size_t length = 0;
    ULONGLONG deadline = GetTickCount64() + 5000;
    while (length < sizeof(info) - 1 && GetTickCount64() < deadline) {
        DWORD available;
        if (!PeekNamedPipe(output_read, NULL, 0, NULL, &available, NULL)) break;
        if (!available) { Sleep(10); continue; }
        if (!ReadFile(output_read, info + length, 1, &count, NULL) || count != 1) break;
        if (info[length++] == '\n') break;
    }
    info[length] = '\0';
    started = sscanf_s(info, "%u %llx %llx", thread_id, code_address, value_address) == 3;
done:
    if (input_read) CloseHandle(input_read);
    if (output_read) CloseHandle(output_read);
    if (output_write) CloseHandle(output_write);
    return started;
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
    wchar_t cells[SCREEN_WIDTH * SCREEN_HEIGHT];
    DWORD read;
    COORD origin = {0, 0};
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(console_output, &info)) return 0;
    int width = info.dwSize.X, height = info.dwSize.Y;
    if (width < 1 || width > SCREEN_WIDTH || height < 1 || height > SCREEN_HEIGHT) return 0;
    DWORD count = (DWORD)(width * height);
    /* Read one console frame; per-row calls can mix two different redraws. */
    if (!ReadConsoleOutputCharacterW(console_output, cells, count, origin, &read) || read != count) return 0;
    for (int row = 0; row < height; row++) {
        wchar_t *line = snapshot + row * (width + 1);
        wmemcpy(line, cells + row * width, (size_t)width);
        line[width] = L'\n';
    }
    snapshot[height * (width + 1)] = L'\0';
    return 1;
}

static void print_screen(void)
{
    /* ASCII keeps captured evidence readable regardless of the runner code page. */
    for (const wchar_t *text = snapshot; *text; text++)
        putchar(*text == L'\n' || (*text >= L' ' && *text <= L'~') ? (int)*text : '|');
    fflush(stdout);
}
