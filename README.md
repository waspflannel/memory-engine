
# MemForge

A Windows x64 terminal application for inspecting process memory. Includes process
selection, exact scans, saved addresses and locks, a hex editor, disassembly, and
a native debugger. The executable is portable; no additional runtime is required.

## Build and test

Use Visual Studio's C++ build tools and CMake:

```powershell
cmake -S . -B ../build -A x64
cmake --build ../build --config Release
ctest --test-dir ../build -C Release --output-on-failure
../build/Release/memforge.exe
```

`Tab` cycles between the sidebar, panel and command bar. `Esc` returns to the
sidebar; `?` opens the current panel's help. Commands also work from the command bar.

## Debugger

Attach to a process first, then use these commands:

| Command | Action |
|---|---|
| `debug` | Start debugging the selected target; pause at the initial attach event. |
| `break` | Request a pause while the target runs. |
| `continue` | Resume execution from a pause. |
| `swbreak <hex_address>` | Set a persistent software execution breakpoint. |
| `hwbreak <thread_id> <hex_address>` | Set a hardware execution breakpoint on one thread. |
| `delbreak <index>` | Remove a breakpoint using its displayed index. |
| `undebug` | Restore debugger changes and end the debug session. |

Set and remove breakpoints while paused. The debugger panel displays the stopped
thread, its general-purpose registers, RIP, RSP, flags, and breakpoint indices.
Use arrows or Page Up/Down to scroll; `d` opens disassembly at the paused RIP.
Software breakpoints temporarily replace one instruction byte with `INT3`; resume
executes the original instruction and rearms the breakpoint. Hardware breakpoints
use up to four available debug-register slots per thread and leave code unchanged.

Debugger support is limited to native x64 targets. Hardware breakpoints apply only
to the specified thread; they are execution breakpoints, not data watchpoints.
The session tracks at most 32 breakpoints. Debugger commands run on the UI thread
and events are polled without blocking input. Detach and quit restore modified
bytes and debug-register slots before releasing the target. A cleanup error keeps
the session available for retry and reports the failure.

The debugger regression test launches its own hidden target with a known machine
instruction, checks real breakpoint hits and register values, then verifies that
the process continues after cleanup. Other tests cover the existing memory tools
and exercise the actual executable through console keyboard events.
