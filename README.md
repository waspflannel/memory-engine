
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

## Watch a value

Select a numeric Scanner result or Address Table entry and press **K**. MemForge
watches that one value across the target's threads. When a target instruction
writes different bytes, execution pauses and the Debugger panel shows the value
before and after, the stopped thread's registers, and instructions at its RIP.
Writes that leave the value unchanged are skipped automatically.

Three actions sit at the bottom of the panel:

- **C — Continue:** resume and wait for the next change.
- **S — Stop watching:** remove the watch and resume; keep the process attached
  for scanning and memory editing.
- **D — Detach:** remove the watch, resume, and disconnect from the process.

The watch starts automatically; there is no separate debugger attach, thread ID,
execution address, or breakpoint list to manage. Arrow keys and Page Up/Down
scroll the information if the terminal is small. `?` opens help.

From the command bar, use `watch <hex_address> <type>`, `continue`, `unwatch`, or
`detach`. Numeric types are `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64`,
`f32`, and `f64`. Only one watch is active at a time; stop it before choosing another.

This supports native x64 targets and naturally aligned values of 1, 2, 4, or 8
bytes. Strings and byte arrays are not supported. A data watch stops **after** a
write: displayed RIP identifies the next instruction, not necessarily the exact
instruction that performed the write. Changes made externally through memory
editing are not target CPU writes and do not trigger the watch.

The watch leaves target code unchanged. Stop, detach, and quit restore the debug
register slots it used; cleanup failures retain the session and report an error.
The regression suite uses its own target process and real console keyboard input.
