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

static int paused(Debugger *debugger, DebuggerState *state)
{
    ULONGLONG deadline = GetTickCount64() + 5000;
    do {
        DebuggerError error = debugger_poll(debugger);
        if (error != DEBUGGER_OK) {
            fprintf(stderr, "poll: %s\n", debugger_error_string(error));
            return 0;
        }
        debugger_get_state(debugger, state);
        if (state->paused) return 1;
        if (!state->attached) return 0;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    return 0;
}

static int read_at(HANDLE process, unsigned long long address, void *value, SIZE_T size)
{
    SIZE_T received;
    return ReadProcessMemory(process, (const void *)(UINT_PTR)address,
                             value, size, &received) && received == size;
}

static int command(HANDLE input, char value)
{
    DWORD sent;
    return WriteFile(input, &value, 1, &sent, NULL) && sent == 1;
}

static int debug_context(HANDLE thread, CONTEXT *context)
{
    BOOL result;
    memset(context, 0, sizeof(*context));
    context->ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (SuspendThread(thread) == (DWORD)-1) return 0;
    result = GetThreadContext(thread, context);
    if (ResumeThread(thread) == (DWORD)-1) return 0;
    return result != FALSE;
}

static int set_debug_context(HANDLE thread, CONTEXT *context)
{
    BOOL result;
    context->ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (SuspendThread(thread) == (DWORD)-1) return 0;
    result = SetThreadContext(thread, context);
    if (ResumeThread(thread) == (DWORD)-1) return 0;
    return result != FALSE;
}

int main(int argc, char **argv)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE output = NULL, child_output = NULL, input = NULL, child_input = NULL;
    PROCESS_INFORMATION child = {0};
    STARTUPINFOW startup = {0};
    wchar_t child_command[] = L"debugger_target.exe";
    char banner[256] = {0};
    size_t used = 0;
    unsigned int tid = 0, sw, hw[4], extra;
    unsigned long long code = 0, counter_address = 0, handled_address = 0;
    unsigned long long heartbeat_address = 0;
    unsigned char original = 0, byte = 0;
    LONG before, after, heartbeat_before, heartbeat_after;
    CONTEXT baseline, context;
    MEMORY_BASIC_INFORMATION memory;
    Target target = {0};
    Debugger *debugger = NULL;
    DebuggerState state;
    ULONGLONG deadline;
    DWORD handles_before, handles_after, exit_code;

    REQUIRE(CreatePipe(&output, &child_output, &sa, 0) &&
            CreatePipe(&child_input, &input, &sa, 0), "create fixture pipes");
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
        if (!PeekNamedPipe(output, NULL, 0, NULL, &available, NULL))
            REQUIRE(0, "fixture output available");
        if (!available) { Sleep(1); continue; }
        REQUIRE(ReadFile(output, banner + used, (DWORD)(sizeof(banner) - 1 - used),
                         &received, NULL), "read fixture addresses");
        used += received;
        banner[used] = '\0';
    }
    REQUIRE(sscanf_s(banner, "%u %llx %llx %llx %llx", &tid, &code, &counter_address,
                     &handled_address, &heartbeat_address) == 5,
            "fixture reports instruction, thread and counters");
    REQUIRE(process_attach(child.dwProcessId, &target) == PLATFORM_OK, "open fixture process");
    REQUIRE(read_at(child.hProcess, code, &original, 1) && original == 0xff,
            "known fixture instruction starts with original byte");
    REQUIRE(debug_context(child.hThread, &baseline), "capture original debug registers");

    check(debugger_attach(NULL, &debugger) == DEBUGGER_ERR_INVALID_PARAM && !debugger,
          "invalid attach fails without creating a session");
    {
        Target self = {0};
        self.pid = GetCurrentProcessId();
        self.handle = GetCurrentProcess();
        check(debugger_attach(&self, &debugger) == DEBUGGER_ERR_UNSUPPORTED && !debugger,
              "unsupported self-debugging fails before starting a session");
    }
    REQUIRE(debugger_attach(&target, &debugger) == DEBUGGER_OK, "attach debugger");
    REQUIRE(paused(debugger, &state), "initial attach pauses through bounded event polling");
    check(state.registers_valid && state.registers.rip && state.registers.rsp && state.thread_id,
          "initial pause exposes valid instruction/stack pointers and thread");
    check(debugger_add_software(debugger, 1, &extra) != DEBUGGER_OK,
          "unmapped software breakpoint fails loudly");
    check(debugger_add_hardware(debugger, 0, code, &extra) != DEBUGGER_OK,
          "invalid hardware thread fails loudly");
    check(debugger_add_hardware(debugger, 0xffffffffu, code, &extra) != DEBUGGER_OK,
          "unavailable thread/context fails loudly");
    check(debugger_add_hardware(debugger, tid, 1, &extra) != DEBUGGER_OK,
          "unmapped hardware instruction fails loudly");
    check(debugger_remove(debugger, DEBUGGER_MAX_BREAKPOINTS) != DEBUGGER_OK,
          "invalid breakpoint index fails loudly");

    REQUIRE(debugger_add_software(debugger, code, &sw) == DEBUGGER_OK, "arm software breakpoint");
    check(read_at(child.hProcess, code, &byte, 1) && byte == 0xcc, "software arm installs INT3");
    check(VirtualQueryEx(child.hProcess, (const void *)(UINT_PTR)code, &memory, sizeof(memory)) &&
          memory.Protect == PAGE_EXECUTE_READ, "software patch preserves executable page protection");
    if (argc == 2 && strcmp(argv[1], "--terminated-paused") == 0) {
        REQUIRE(TerminateProcess(child.hProcess, 7), "terminate owned fixture while debugger is paused");
        REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger,
                "detach releases terminated target with armed software breakpoint");
        check(WaitForSingleObject(child.hProcess, 1000) == WAIT_OBJECT_0,
              "terminated paused target finishes exit after debugger cleanup");
        goto cleanup;
    }
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK && paused(debugger, &state),
            "software breakpoint pauses target");
    check(state.thread_id == tid && state.registers_valid && state.registers.rip == code &&
          state.registers.rcx == counter_address && state.registers.rsp != 0,
          "software stop restores RIP and captures the actual argument register");
    check(read_at(child.hProcess, code, &byte, 1) && byte == original,
          "software stop restores instruction before execution");
    REQUIRE(read_at(child.hProcess, counter_address, &before, sizeof(before)), "read paused counter");
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK && paused(debugger, &state),
            "persistent software breakpoint rearms and hits again");
    check(state.registers.rip == code && read_at(child.hProcess, counter_address, &after, sizeof(after)) &&
          after == before + 1, "resume executes saved instruction exactly once before next hit");
    REQUIRE(debugger_add_hardware(debugger, tid, code, &hw[0]) == DEBUGGER_OK,
            "arm hardware breakpoint at existing software instruction");
    {
        int saw_software = 0, saw_hardware = 0;
        REQUIRE(read_at(child.hProcess, counter_address, &before, sizeof(before)),
                "read counter before co-located breakpoint sequence");
        for (int hit = 0; hit < 6; hit++) {
            REQUIRE(debugger_continue(debugger) == DEBUGGER_OK && paused(debugger, &state),
                    "continue through co-located software and hardware stops");
            if (state.exception_code == EXCEPTION_BREAKPOINT) saw_software = 1;
            if (state.exception_code == EXCEPTION_SINGLE_STEP) saw_hardware = 1;
        }
        check(saw_software && saw_hardware &&
              read_at(child.hProcess, counter_address, &after, sizeof(after)) && after > before,
              "co-located breakpoint kinds both hit and allow instruction progress");
    }
    REQUIRE(debugger_remove(debugger, hw[0]) == DEBUGGER_OK, "remove co-located hardware breakpoint");
    REQUIRE(debugger_remove(debugger, sw) == DEBUGGER_OK, "remove paused software breakpoint");
    check(read_at(child.hProcess, code, &byte, 1) && byte == original, "software removal preserves code");

    for (unsigned int i = 0; i < 4; i++) {
        REQUIRE(debugger_add_hardware(debugger, tid, code + i * 16, &hw[i]) == DEBUGGER_OK,
                "arm per-thread hardware execution slot");
    }
    check(debugger_add_hardware(debugger, tid, code + 64, &extra) == DEBUGGER_ERR_CAPACITY,
          "fifth hardware breakpoint reports slot exhaustion");
    check(read_at(child.hProcess, code, &byte, 1) && byte == original,
          "hardware breakpoints never patch code");
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK && paused(debugger, &state),
            "hardware execution breakpoint pauses target");
    check(state.thread_id == tid && state.registers_valid && state.registers.rip == code &&
          state.registers.rcx == counter_address, "hardware stop shows correct thread, RIP and argument");
    REQUIRE(read_at(child.hProcess, counter_address, &before, sizeof(before)), "read hardware stop counter");
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK && paused(debugger, &state),
            "hardware resume reaches subsequent hit");
    check(read_at(child.hProcess, counter_address, &after, sizeof(after)) && after == before + 1,
          "hardware resume executes breakpointed instruction");
    for (unsigned int i = 0; i < 4; i++)
        REQUIRE(debugger_remove(debugger, hw[i]) == DEBUGGER_OK, "remove hardware execution slot");
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK, "continue with breakpoints removed");
    REQUIRE(debugger_pause(debugger) == DEBUGGER_OK && paused(debugger, &state), "pause running target on demand");
    check(state.registers_valid && state.registers.rip && state.registers.rsp,
          "manual pause captures live register snapshot");

    /* Detach while both kinds are armed must restore code and the thread's DRs. */
    REQUIRE(debugger_add_software(debugger, code, &sw) == DEBUGGER_OK &&
            debugger_add_hardware(debugger, tid, code + 16, &hw[0]) == DEBUGGER_OK,
            "arm both breakpoint kinds before detach");
    REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger, "detach releases session");
    /* Windows retains the calling thread's debug object after its first use. */
    REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &handles_before), "count handles after first debug session");
    check(read_at(child.hProcess, code, &byte, 1) && byte == original, "detach restores armed software byte");
    check(VirtualQueryEx(child.hProcess, (const void *)(UINT_PTR)code, &memory, sizeof(memory)) &&
          memory.Protect == PAGE_EXECUTE_READ, "detach preserves original page protection");
    REQUIRE(debug_context(child.hThread, &context), "read debug registers after detach");
    check(context.Dr0 == baseline.Dr0 && context.Dr1 == baseline.Dr1 &&
          context.Dr2 == baseline.Dr2 && context.Dr3 == baseline.Dr3 &&
          (context.Dr7 & ~0x400ull) == (baseline.Dr7 & ~0x400ull),
          "detach restores all debug addresses and enable bits");
    REQUIRE(read_at(child.hProcess, counter_address, &before, sizeof(before)), "read detached counter");
    REQUIRE(read_at(child.hProcess, heartbeat_address, &heartbeat_before, sizeof(heartbeat_before)),
            "read peer heartbeat after software rearm and detach");
    Sleep(50);
    check(read_at(child.hProcess, counter_address, &after, sizeof(after)) && after > before,
          "detached target continues normally");
    check(read_at(child.hProcess, heartbeat_address, &heartbeat_after, sizeof(heartbeat_after)) &&
          heartbeat_after > heartbeat_before, "software rearm and detach leave the peer thread running");

    REQUIRE(debugger_attach(&target, &debugger) == DEBUGGER_OK && paused(debugger, &state) &&
            debugger_add_software(debugger, code, &sw) == DEBUGGER_OK &&
            debugger_continue(debugger) == DEBUGGER_OK && paused(debugger, &state),
            "reattach and stop inside a software breakpoint");
    REQUIRE(read_at(child.hProcess, counter_address, &before, sizeof(before)), "read software hit before detach");
    REQUIRE(read_at(child.hProcess, heartbeat_address, &heartbeat_before, sizeof(heartbeat_before)),
            "read peer heartbeat at software hit");
    REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger,
            "detach at software hit without leaving a pending step");
    Sleep(50);
    check(read_at(child.hProcess, code, &byte, 1) && byte == original &&
          read_at(child.hProcess, counter_address, &after, sizeof(after)) && after > before,
          "detach at software hit restores code and safely executes saved instruction");
    check(read_at(child.hProcess, heartbeat_address, &heartbeat_after, sizeof(heartbeat_after)) &&
          heartbeat_after > heartbeat_before, "detach at software hit releases suspended peer thread");

    context = baseline;
    context.Dr3 = code + 96;
    context.Dr7 = (context.Dr7 & ~((DWORD64)0xf << 28)) | ((DWORD64)1 << 6);
    REQUIRE(set_debug_context(child.hThread, &context), "seed preexisting enabled debug register");
    REQUIRE(debugger_attach(&target, &debugger) == DEBUGGER_OK && paused(debugger, &state),
            "attach with preexisting hardware slot");
    for (unsigned int i = 0; i < 3; i++) {
        REQUIRE(debugger_add_hardware(debugger, tid, code + 16 + i * 16, &hw[i]) == DEBUGGER_OK,
                "use free hardware slot without replacing preexisting slot");
    }
    check(debugger_add_hardware(debugger, tid, code + 64, &extra) == DEBUGGER_ERR_CAPACITY,
          "preexisting enabled slot counts toward hardware capacity");
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK, "resume before running detach");
    REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger, "detach while target is running");
    REQUIRE(debug_context(child.hThread, &context), "read debug registers after running detach");
    /* Reserved DR7 bit 10 can be normalized by the processor/context API.
       Every breakpoint address, enable, type and length bit must match. */
    if (context.Dr0 != baseline.Dr0 || context.Dr1 != baseline.Dr1 ||
        context.Dr2 != baseline.Dr2 || context.Dr3 != code + 96 ||
        (context.Dr7 & ~0x400ull) != ((baseline.Dr7 & ~((DWORD64)0xf << 28) & ~0x400ull) | ((DWORD64)1 << 6)))
        fprintf(stderr, "DR restore: got %llx %llx %llx %llx dr7=%llx expected %llx %llx %llx %llx dr7=%llx\n",
            context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr7,
            baseline.Dr0, baseline.Dr1, baseline.Dr2, code + 96,
            (baseline.Dr7 & ~((DWORD64)0xf << 28)) | ((DWORD64)1 << 6));
    check(context.Dr0 == baseline.Dr0 && context.Dr1 == baseline.Dr1 &&
          context.Dr2 == baseline.Dr2 && context.Dr3 == code + 96 &&
          (context.Dr7 & ~0x400ull) == ((baseline.Dr7 & ~((DWORD64)0xf << 28) & ~0x400ull) | ((DWORD64)1 << 6)),
          "running detach restores the preexisting enabled slot exactly");
    REQUIRE(set_debug_context(child.hThread, &baseline), "clear fixture's seeded hardware slot");

    REQUIRE(debugger_attach(&target, &debugger) == DEBUGGER_OK && paused(debugger, &state),
            "reattach after clean detach");
    REQUIRE(debugger_continue(debugger) == DEBUGGER_OK, "resume for exception forwarding checks");
    for (int expected = 1; expected <= 2; expected++) {
        REQUIRE(command(input, expected == 1 ? 'e' : 'b'), "request fixture-owned exception");
        after = 0;
        deadline = GetTickCount64() + 5000;
        while (after < expected && GetTickCount64() < deadline) {
            if (debugger_poll(debugger) != DEBUGGER_OK) REQUIRE(0, "poll fixture-owned exception");
            debugger_get_state(debugger, &state);
            if (state.paused) REQUIRE(debugger_continue(debugger) == DEBUGGER_OK, "forward foreign exception");
            if (!read_at(child.hProcess, handled_address, &after, sizeof(after)))
                REQUIRE(0, "read fixture exception handler count");
            Sleep(1);
        }
        check(after == expected, expected == 1 ? "unowned exception reaches target exception handler" :
              "unowned INT3 exception reaches target exception handler");
    }
    REQUIRE(command(input, 'u'), "request controlled unhandled target exception");
    deadline = GetTickCount64() + 5000;
    do {
        if (debugger_poll(debugger) != DEBUGGER_OK) REQUIRE(0, "poll unhandled target exit");
        debugger_get_state(debugger, &state);
        if (!state.attached) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    check(!state.attached && !state.paused && !state.registers_valid,
          "target exit clears attachment, pause and register state");
    REQUIRE(debugger_detach(&debugger) == DEBUGGER_OK && !debugger, "release exited debugger session");
    check(WaitForSingleObject(child.hProcess, 1000) == WAIT_OBJECT_0, "fixture exited without being killed");
    check(GetExitCodeProcess(child.hProcess, &exit_code) && exit_code == 0xe0424243,
          "unowned second-chance exception determines target exit code");
    REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &handles_after), "count handles after debug sessions");
    if (handles_after > handles_before)
        fprintf(stderr, "Debug handles: before=%lu after=%lu\n", handles_before, handles_after);
    check(handles_after <= handles_before,
          "repeated debug sessions release native event and duplicated thread handles");

cleanup:
    if (debugger) debugger_detach(&debugger);
    process_detach(&target);
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
