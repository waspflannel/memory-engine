A lightweight Windows tool for inspecting and editing running programs’ memory. Written in C.

some features

- Process browser — Show all running processes and attach to them.
- Memory scanner — Search for numbers, strings, or byte sequences, then narrow results.
- Memory editor — Read and write bytes at specific addresses.
- Address table — Save and label addresses, monitor values, and lock them to a chosen value.
- Hex viewer — Browse and edit memory as hexadecimal bytes and ASCII.
- Disassembler — View x64 instructions and follow direct calls and jumps.
- Value debugger — Watch a numeric value and pause when the program changes it.
- DLL loader — Load an x64 DLL into the attached process.
- Pointer scanner — Find pointer chains and check them again after a process restart.
- Structure inspector — View memory as named numeric fields and highlight changes.


Build and run
Requires Windows x64, CMake, and Visual Studio Build Tools with the Desktop development with C++ workload.
From the repository directory containing CMakeLists.txt:
cmake -S . -B build -A x64
cmake --build build --config Release
.\build\Release\memforge.exe
