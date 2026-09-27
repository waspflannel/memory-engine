#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "core/pointer_scan/pointer_scan.h"
#include "test/test.h"

typedef struct {
    PROCESS_INFORMATION process;
    HANDLE input, output;
    Target target;
    unsigned long long root_three, root_two, value;
} Fixture;

static int read_line(HANDLE pipe, char *line, size_t capacity)
{
    size_t used = 0;
    ULONGLONG deadline = GetTickCount64() + 5000;
    while (used + 1 < capacity && GetTickCount64() < deadline) {
        DWORD available, received;
        if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) return 0;
        if (!available) { Sleep(1); continue; }
        if (!ReadFile(pipe, line + used, 1, &received, NULL) || received != 1) return 0;
        if (line[used++] == '\n') { line[used] = 0; return 1; }
    }
    return 0;
}

static void stop_fixture(Fixture *fixture)
{
    process_detach(&fixture->target);
    if (fixture->input) CloseHandle(fixture->input);
    if (fixture->output) CloseHandle(fixture->output);
    if (fixture->process.hProcess) {
        if (WaitForSingleObject(fixture->process.hProcess, 2000) != WAIT_OBJECT_0) {
            TerminateProcess(fixture->process.hProcess, 1);
            WaitForSingleObject(fixture->process.hProcess, 2000);
        }
        CloseHandle(fixture->process.hProcess);
    }
    if (fixture->process.hThread) CloseHandle(fixture->process.hThread);
    *fixture = (Fixture){0};
}

static int start_fixture(Fixture *fixture)
{
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    STARTUPINFOW startup = {0};
    HANDLE child_input = NULL, child_output = NULL;
    wchar_t command[] = L"pointer_target.exe";
    char line[160];
    int success = 0;
    if (!CreatePipe(&child_input, &fixture->input, &security, 0) ||
        !CreatePipe(&fixture->output, &child_output, &security, 0)) goto done;
    if (!SetHandleInformation(fixture->input, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(fixture->output, HANDLE_FLAG_INHERIT, 0)) goto done;
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = child_input;
    startup.hStdOutput = startup.hStdError = child_output;
    if (!CreateProcessW(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &fixture->process)) goto done;
    if (!read_line(fixture->output, line, sizeof(line)) ||
        sscanf_s(line, "%llx %llx %llx", &fixture->root_three, &fixture->root_two, &fixture->value) != 3) goto done;
    success = process_attach(fixture->process.dwProcessId, &fixture->target) == PLATFORM_OK;
done:
    if (child_input) CloseHandle(child_input);
    if (child_output) CloseHandle(child_output);
    if (!success) stop_fixture(fixture);
    return success;
}

static int command_fixture(Fixture *fixture, char command)
{
    DWORD written;
    char line[16];
    return WriteFile(fixture->input, &command, 1, &written, NULL) && written == 1 &&
           read_line(fixture->output, line, sizeof(line)) && strcmp(line, "ok\r\n") == 0;
}

static PointerPath *find_chain(PointerResults *results, unsigned long long root_offset, unsigned int depth)
{
    for (size_t i = 0; i < results->count; i++) {
        PointerPath *path = &results->paths[i];
        if (path->root_offset != root_offset || path->depth != depth) continue;
        if ((depth == 2 && path->offsets[0] == 32 && path->offsets[1] == 40) ||
            (depth == 3 && path->offsets[0] == 24 && path->offsets[1] == 32 && path->offsets[2] == 40)) return path;
    }
    return NULL;
}

#define REQUIRE(condition, message) do { int passed = (condition); check(passed, message); if (!passed) goto cleanup; } while (0)

int main(void)
{
    Fixture fixture = {0};
    PointerResults results = {0}, cancelled = {0};
    PointerPath *known, saved;
    atomic_bool cancel;
    atomic_init(&cancel, true);
    REQUIRE(start_fixture(&fixture), "launch deterministic pointer fixture");
    check(pointer_scan(&fixture.target, fixture.value, 0, 64, NULL, &results) == PLATFORM_ERR_INVALID_PARAM,
          "reject zero depth");
    check(pointer_scan(&fixture.target, fixture.value, 4, 64, NULL, &results) == PLATFORM_ERR_INVALID_PARAM,
          "reject depth above three");
    check(pointer_scan(&fixture.target, fixture.value, 2, 4097, NULL, &results) == PLATFORM_ERR_INVALID_PARAM,
          "reject excessive offset");
    REQUIRE(pointer_scan(&fixture.target, fixture.value, 3, 64, &cancel, &cancelled) == PLATFORM_OK &&
            cancelled.cancelled && !cancelled.count, "cancelled scan does no indexing work");
    REQUIRE(pointer_scan(&fixture.target, fixture.value, 2, 64, NULL, &results) == PLATFORM_OK,
            "scan two dereferences with bounded offsets");
    known = find_chain(&results, fixture.root_two - fixture.target.base, 2);
    REQUIRE(known != NULL, "find static root -> heap+32 -> value+40");
    check(!find_chain(&results, fixture.root_three - fixture.target.base, 3), "depth limit excludes longer path");
    REQUIRE(pointer_scan(&fixture.target, fixture.value, 3, 64, NULL, &results) == PLATFORM_OK,
            "scan three dereferences");
    known = find_chain(&results, fixture.root_three - fixture.target.base, 3);
    REQUIRE(known != NULL, "find static root -> heap+24 -> heap+32 -> value+40");
    saved = *known;
    saved.resolved_address = 0;
    REQUIRE(pointer_resolve(&fixture.target, results.module_name, &saved) == PLATFORM_OK &&
            saved.resolved_address == fixture.value, "resolve complete chain from executable-relative root");
    REQUIRE(command_fixture(&fixture, 'x'), "make intermediate page unreadable");
    check(pointer_resolve(&fixture.target, results.module_name, &saved) != PLATFORM_OK && !saved.resolved_address,
          "unreadable intermediate pointer fails and clears old address");
    REQUIRE(command_fixture(&fixture, 'r'), "restore intermediate page");
    PointerPath invalid = saved;
    invalid.root_offset = ~0ull;
    check(pointer_resolve(&fixture.target, results.module_name, &invalid) != PLATFORM_OK && !invalid.resolved_address,
          "reject root offset outside current module");
    check(pointer_resolve(&fixture.target, L"different.exe", &saved) == PLATFORM_ERR_MODULE_FAILED && !saved.resolved_address,
          "reject a different executable and clear previous address");
    stop_fixture(&fixture);
    REQUIRE(start_fixture(&fixture), "restart target with fresh heap allocation");
    REQUIRE(pointer_resolve(&fixture.target, results.module_name, &saved) == PLATFORM_OK &&
            saved.resolved_address == fixture.value, "saved relative chain resolves after process restart");
    REQUIRE(pointer_filter(&fixture.target, fixture.value, &results) == PLATFORM_OK,
            "filter previous paths against restarted target value");
    REQUIRE(find_chain(&results, fixture.root_three - fixture.target.base, 3) != NULL,
            "restart filter retains the known three-level path");
    REQUIRE(command_fixture(&fixture, 'c'), "populate more executable roots than result cap");
    REQUIRE(pointer_scan(&fixture.target, fixture.value, 1, 64, NULL, &results) == PLATFORM_OK,
            "bounded scan completes on many duplicate roots");
    check(results.count == POINTER_MAX_RESULTS && (results.truncated & POINTER_LIMIT_RESULTS),
          "result cap is enforced and explicitly reported");
cleanup:
    pointer_results_free(&results);
    pointer_results_free(&cancelled);
    stop_fixture(&fixture);
    printf("pointer tests: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
