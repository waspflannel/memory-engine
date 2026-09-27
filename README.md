
# MemForge

A Windows x64 terminal application for inspecting process memory. Includes process
selection, exact scans, saved addresses and locks, a hex editor, disassembly, and
a native debugger. The executable is portable; no additional runtime is required.

## DLLs, pointers and structures

Attach a process first. These tools work independently of the debugger.

- **DLL loading:** `inject "C:\path with spaces\tool.dll"` loads an existing x64
  DLL through the standard Windows loader. The status line reports completion.
  Stop any debugger watch first; wait for loading before detach or quit. The DLL
  remains loaded after detach. No manual mapping or automatic unloading.
- **Pointer scanning:** select a Scanner or Address Table value and press **P**,
  or use `pointers <hex_address> [depth] [max_offset]`. Defaults: two dereferences,
  maximum offset 1024 bytes. Limits: depth 1–3, nonnegative offset 0–4096 bytes;
  both arguments are decimal. Paths start at an aligned pointer in the main
  executable, displayed as `program.exe+root -> +offset -> +offset`.
  **Up/Down** selects, **Left/Right** reveals long paths, **R** resolves again,
  **Enter** opens the resolved address in Hex View, and **C** cancels a scan.
  Paths remain in this session across detach: reattach the same executable and
  use `pointerfilter <new_hex_address>` to retain paths still reaching your value.
- **Structure inspection:** select a value and press **I**, or use
  `structure <hex_address> [size]` (1–256 bytes, default 256).
  **R** refreshes; `*` marks changed rows/fields, `??` means unreadable. Scroll with
  arrows or Page Up/Down. Add a typed field with `field <hex_offset> <type> <label>`,
  for example `field 10 f32 health`. Reusing an offset replaces its field.
  Up to 32 fields; labels last until another structure opens or you detach.

Pointer scanning targets native x64 processes and aligned eight-byte pointers.
It uses one bounded memory snapshot: at most 256 MiB scanned, one million indexed
pointers, 16,384 candidates per level and 512 results. `PARTIAL` means a limit was
reached; skipped unreadable bytes are reported. A path is a candidate, not a
guarantee across program versions. Scan again with tighter limits or filter after
a restart. There is no pointer database or saved structure-layout format.

DLL paths must fit the 255-character command line and the Windows 259-character
absolute-path limit used by this implementation. Loader failures report an error;
a pending loader retains its resources until completion or target exit.

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
