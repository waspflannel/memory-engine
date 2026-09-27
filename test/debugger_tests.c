#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "core/debugger/debugger.h"
#include "test/test.h"

#define REQUIRE(condition, message) do { \
    int passed = (condition); check(passed, message); if (!passed) goto cleanup; \
} while (0)

static int read_at(HANDLE process, unsigned long long address, void *value, SIZE_T size)
{
    SIZE_T received;
    return ReadProcessMemory(process, (const void *)(UINT_PTR)address, value, size, &received) && received == size;
}

static int command(HANDLE input, char value)
{
    DWORD sent;
    return WriteFile(input, &value, 1, &sent, NULL) && sent == 1;
}

static int wait_state(Debugger *debugger, DebuggerState *state, int paused)
{
    ULONGLONG deadline = GetTickCount64() + 5000;
    do {
        DebuggerError error = debugger_poll(debugger);
        if (error != DEBUGGER_OK) {
            fprintf(stderr, "poll: %s\n", debugger_error_string(error));
            return 0;
        }
        debugger_get_state(debugger, state);
        if (!state->attached) return 0;
        if (state->watching && state->paused == paused) return 1;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    return 0;
}

/* A fixture acknowledgement proves the instruction ran; elapsed time alone cannot. */
static int wait_counter(Debugger *debugger, HANDLE process, unsigned long long address, LONG expected)
{
    ULONGLONG deadline = GetTickCount64() + 5000;
    do {
        LONG value;
        DebuggerState state = {0};
        if (debugger && debugger_poll(debugger) != DEBUGGER_OK) return 0;
        if (debugger) {
            debugger_get_state(debugger, &state);
            if (state.paused || !state.attached) return 0;
        }
        if (!read_at(process, address, &value, sizeof(value))) return 0;
        if (value >= expected) return 1;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    return 0;
}

static int debug_context(HANDLE thread, CONTEXT *context, int write)
{
    BOOL result;
    context->ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (SuspendThread(thread) == (DWORD)-1) return 0;
    result = write ? SetThreadContext(thread, context) : GetThreadContext(thread, context);
    if (ResumeThread(thread) == (DWORD)-1) return 0;
    return result != FALSE;
}

static int same_debug_registers(const CONTEXT *left, const CONTEXT *right)
{
    /* Windows may normalize reserved DR7 bit 10. */
    return left->Dr0 == right->Dr0 && left->Dr1 == right->Dr1 &&
           left->Dr2 == right->Dr2 && left->Dr3 == right->Dr3 &&
           (left->Dr7 & ~0x400ull) == (right->Dr7 & ~0x400ull);
}

int main(int argc, char **argv)
{
    SECURITY_ATTRIBUTES security = { sizeof(security), NULL, TRUE };
    HANDLE output = NULL, child_output = NULL, input = NULL, child_input = NULL, peer = NULL;
    PROCESS_INFORMATION child = {0};
    STARTUPINFOW startup = {0};
    wchar_t child_command[] = L"debugger_target.exe";
    char banner[256] = {0};
    size_t used = 0;
    unsigned int tid = 0, peer_tid = 0;
    unsigned long long code = 0, address = 0, handled_address = 0, heartbeat_address = 0, completed_address = 0;
    LONG before, after, completed = 0;
    CONTEXT baseline = {0}, peer_baseline = {0}, foreign, context = {0};
    Target target = {0};
    Debugger *debugger = NULL;
    DebuggerState state = {0};
    ULONGLONG deadline;
    DWORD handles_before, handles_after, exit_code;

    REQUIRE(CreatePipe(&output, &child_output, &security, 0) &&
            CreatePipe(&child_input, &input, &security, 0), "create fixture pipes");
    REQUIRE(SetHandleInformation(output, HANDLE_FLAG_INHERIT, 0) &&
            SetHandleInformation(input, HANDLE_FLAG_INHERIT, 0), "limit inherited pipe ends");
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = child_output;
    startup.hStdError = child_output;
    startup.hStdInput = child_input;
    REQUIRE(CreateProcessW(NULL, child_command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                           NULL, NULL, &startup, &child), "start controlled x64 fixture hidden");
    CloseHandle(child_output); child_output = NULL;
    CloseHandle(child_input); child_input = NULL;
    deadline = GetTickCount64() + 5000;
    while (!strchr(banner, '\n') && used < sizeof(banner) - 1 && GetTickCount64() < deadline) {
        DWORD available, received;
        REQUIRE(PeekNamedPipe(output, NULL, 0, NULL, &available, NULL), "fixture output available");
        if (!available) { Sleep(1); continue; }
        REQUIRE(ReadFile(output, banner + used, (DWORD)(sizeof(banner) - 1 - used),
                         &received, NULL), "read fixture addresses");
        used += received;
        banner[used] = '\0';
    }
    REQUIRE(sscanf_s(banner, "%u %llx %llx %llx %llx %u %llx", &tid, &code, &address,
                     &handled_address, &heartbeat_address, &peer_tid, &completed_address) == 7,
            "fixture reports known code, value, threads and acknowledgement");
    REQUIRE(process_attach(child.dwProcessId, &target) == PLATFORM_OK, "open fixture process");
    peer = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, peer_tid);
    REQUIRE(peer && debug_context(child.hThread, &baseline, 0) && debug_context(peer, &peer_baseline, 0),
            "capture original main and peer debug registers");

    check(debugger_watch(NULL, address, 4, &debugger) == DEBUGGER_ERR_INVALID_PARAM && !debugger,
          "invalid target does not create a session");
    check(debugger_watch(&target, address, 3, &debugger) == DEBUGGER_ERR_INVALID_PARAM && !debugger,
          "unsupported value width is rejected");
    check(debugger_watch(&target, address + 1, 4, &debugger) == DEBUGGER_ERR_INVALID_PARAM && !debugger,
          "misaligned value is rejected");
    check(debugger_watch(&target, 0x10000, 4, &debugger) == DEBUGGER_ERR_READ && !debugger,
          "unreadable watched value fails before attaching");
    REQUIRE(debugger_watch(&target, address, 4, &debugger) == DEBUGGER_OK &&
            wait_state(debugger, &state, 0), "watch arms all initial threads and resumes automatically");
    check(!state.paused && state.address == address && state.size == 4,
          "watch state identifies one running value");
    check(debugger_continue(debugger) == DEBUGGER_ERR_NOT_PAUSED, "continue requires an actual value change");
    REQUIRE(command(input, 's') && wait_counter(debugger, child.hProcess, completed_address, ++completed),
            "same-value CPU write completes without pausing");
    REQUIRE(command(input, 'i') && wait_state(debugger, &state, 1), "changed value pauses target");
    memcpy(&before, state.before, sizeof(before));
    memcpy(&after, state.after, sizeof(after));
    check(state.value_valid && before == 0 && after == 1 && state.registers_valid &&
          state.thread_id == tid && state.registers.rip == code + 2 && state.registers.rcx == address,
          "change exposes before/after and actual post-write RIP, argument and thread");
    if (argc == 2 && strcmp(argv[1], "--terminated-paused") == 0) {
        REQUIRE(TerminateProcess(child.hProcess, 7), "terminate controlled paused fixture");
        REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger,
                "terminated paused target releases watch session");
        check(WaitForSingleObject(child.hProcess, 1000) == WAIT_OBJECT_0, "terminated target completes exit");
        goto cleanup;
    }
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK &&
            wait_counter(debugger, child.hProcess, completed_address, ++completed), "continue finishes watched write");
    REQUIRE(command(input, 'i') && wait_state(debugger, &state, 1), "watch catches another main-thread change");
    memcpy(&before, state.before, sizeof(before));
    memcpy(&after, state.after, sizeof(after));
    check(before == 1 && after == 2, "continued watch updates the comparison baseline");
    {
        LONG edited = 100;
        SIZE_T written;
        REQUIRE(WriteProcessMemory(child.hProcess, (void *)(UINT_PTR)address, &edited, sizeof(edited), &written) &&
                written == sizeof(edited), "edit watched value while target is paused");
    }
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK &&
            wait_counter(debugger, child.hProcess, completed_address, ++completed), "resume second change");
    REQUIRE(command(input, 's') && wait_counter(debugger, child.hProcess, completed_address, ++completed),
            "continue refreshes baseline after paused external edit");
    REQUIRE(command(input, 'p') && wait_state(debugger, &state, 1), "existing peer thread writes are watched");
    check(state.thread_id == peer_tid && state.registers.rip == code + 2,
          "peer stop reports the writing thread and next instruction");
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK &&
            wait_counter(debugger, child.hProcess, completed_address, ++completed), "resume existing peer");
    REQUIRE(command(input, 'n') && wait_state(debugger, &state, 1), "new thread is watched before its first write");
    check(state.thread_id != tid && state.thread_id != peer_tid && state.registers.rip == code + 2,
          "new-thread change reports its actual writer");
    REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger, "stop watching a paused target releases session");
    REQUIRE(wait_counter(NULL, child.hProcess, completed_address, ++completed), "stopped watch resumes paused writer");
    REQUIRE(debug_context(child.hThread, &context, 0), "read main registers after stop");
    check(same_debug_registers(&context, &baseline), "stop restores main debug registers");
    REQUIRE(debug_context(peer, &context, 0), "read peer registers after stop");
    check(same_debug_registers(&context, &peer_baseline), "stop restores peer debug registers");
    REQUIRE(read_at(child.hProcess, heartbeat_address, &before, sizeof(before)), "read live peer heartbeat");
    check(wait_counter(NULL, child.hProcess, heartbeat_address, before + 1), "target peer stays alive after stop");
    /* Windows retains the debug object after its first use on this test thread. */
    REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &handles_before), "count handles after first session");

    foreign = baseline;
    foreign.Dr3 = code + 96;
    foreign.Dr7 = (foreign.Dr7 & ~((DWORD64)0xf << 28)) | ((DWORD64)1 << 6);
    REQUIRE(debug_context(child.hThread, &foreign, 1), "seed foreign execution slot outside executed code");
    for (unsigned int width = 1; width <= 8; width *= 2) {
        REQUIRE(debugger_watch(&target, address, width, &debugger) == DEBUGGER_OK && wait_state(debugger, &state, 0),
                "arm supported numeric width alongside foreign slot");
        REQUIRE(command(input, (char)('0' + width)) && wait_state(debugger, &state, 1),
                "supported width catches a write to its final byte");
        check(state.size == width && state.after[width - 1] == (unsigned char)(state.before[width - 1] + 1) &&
              state.registers.rcx == address + width - 1 && state.registers.rip == code + 34,
              "watch covers its complete width and identifies final-byte write");
        REQUIRE(debugger_continue(debugger) == DEBUGGER_OK &&
                wait_counter(debugger, child.hProcess, completed_address, ++completed), "resume numeric watch");
        REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger, "running watch detaches cleanly");
        REQUIRE(debug_context(child.hThread, &context, 0), "read restored foreign slot");
        check(same_debug_registers(&context, &foreign), "detach preserves preexisting debug slot and other registers");
    }
    REQUIRE(debug_context(child.hThread, &baseline, 1), "restore fixture's original debug registers");
    {
        CONTEXT full = baseline;
        DebuggerError error = DEBUGGER_OK;
        full.Dr0 = code + 32; full.Dr1 = code + 48; full.Dr2 = code + 64; full.Dr3 = code + 80;
        full.Dr7 = (full.Dr7 & ~0xffff00ffull) | 0x55;
        REQUIRE(debug_context(child.hThread, &full, 1), "occupy all main slots with foreign breakpoints");
        REQUIRE(debugger_watch(&target, address, 4, &debugger) == DEBUGGER_OK,
                "begin watch with exhausted main slots");
        deadline = GetTickCount64() + 5000;
        do {
            error = debugger_poll(debugger);
            if (error != DEBUGGER_OK) break;
            Sleep(1);
        } while (GetTickCount64() < deadline);
        check(error == DEBUGGER_ERR_CAPACITY, "slot exhaustion fails loudly instead of silently skipping a thread");
        REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger, "failed setup remains safely detachable");
        REQUIRE(debug_context(peer, &context, 0), "read partially armed peer after cleanup");
        check(same_debug_registers(&context, &peer_baseline), "failed setup restores already armed peer");
        REQUIRE(debug_context(child.hThread, &context, 0), "read full main slots after cleanup");
        check(same_debug_registers(&context, &full), "failed setup preserves every foreign slot");
        REQUIRE(debug_context(child.hThread, &baseline, 1), "clear seeded main slots");
    }
    REQUIRE(debugger_watch(&target, address, 4, &debugger) == DEBUGGER_OK && wait_state(debugger, &state, 0),
            "restart watch for exception forwarding");
    for (LONG expected = 1; expected <= 2; expected++) {
        REQUIRE(command(input, expected == 1 ? 'e' : 'b') &&
                wait_counter(debugger, child.hProcess, handled_address, expected),
                "foreign exceptions reach target handler without watch stop");
    }
    REQUIRE(command(input, 'u'), "request controlled unhandled exception");
    deadline = GetTickCount64() + 5000;
    do {
        if (debugger_poll(debugger) != DEBUGGER_OK) REQUIRE(0, "poll controlled target exit");
        debugger_get_state(debugger, &state);
        if (!state.attached) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    check(!state.attached && !state.watching && !state.paused && !state.registers_valid,
          "target exit clears active watch and stopped registers");
    REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger, "release exited session");
    check(WaitForSingleObject(child.hProcess, 1000) == WAIT_OBJECT_0 &&
          GetExitCodeProcess(child.hProcess, &exit_code) && exit_code == 0xe0424243,
          "foreign second-chance exception retains its target exit code");
    REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &handles_after), "count handles after repeated watches");
    check(handles_after <= handles_before, "watch cycles release event and tracked thread handles");

cleanup:
    if (debugger) {
        if (debugger_detach(&debugger) != DEBUGGER_OK && child.hProcess) {
            TerminateProcess(child.hProcess, 1);
            debugger_detach(&debugger);
        }
        check(!debugger, "failure cleanup releases debugger session");
    }
    process_detach(&target);
    if (peer) CloseHandle(peer);
    if (input) CloseHandle(input);
    if (child.hProcess) {
        if (WaitForSingleObject(child.hProcess, 1000) == WAIT_TIMEOUT) {
            TerminateProcess(child.hProcess, 1);
            WaitForSingleObject(child.hProcess, 1000);
        }
        CloseHandle(child.hProcess);
    }
    if (child.hThread) CloseHandle(child.hThread);
    if (output) CloseHandle(output);
    if (child_output) CloseHandle(child_output);
    if (child_input) CloseHandle(child_input);
    printf("debugger tests: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
