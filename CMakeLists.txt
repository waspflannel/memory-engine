cmake_minimum_required(VERSION 3.16)
project(MemForge LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_executable(memforge
    tui/main.c
    tui/tui.c
    tui/commands.c
    tui/helpers.c
    tui/render.c
    core/process/process.c
    core/memory/memory.c
    core/scanner/scanner.c
    platform/platform.c
)

target_compile_options(memforge PRIVATE /W4 /WX /wd5105)
target_include_directories(memforge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_target
    test_target/main.c
)
target_compile_options(test_target PRIVATE /W4 /WX)
target_link_libraries(memforge PRIVATE psapi)

add_executable(core_tests
    test/core_tests.c
    core/process/process.c
    core/memory/memory.c
    core/scanner/scanner.c
    platform/platform.c
)
target_compile_options(core_tests PRIVATE /W4 /WX)
target_include_directories(core_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(core_tests PRIVATE psapi)

add_executable(scanner_tests
    test/scanner_tests.c
    core/process/process.c
    core/memory/memory.c
    core/scanner/scanner.c
    platform/platform.c
)
target_compile_options(scanner_tests PRIVATE /W4 /WX /wd5105)
target_include_directories(scanner_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(scanner_tests PRIVATE psapi)

enable_testing()
add_test(NAME core_tests COMMAND core_tests)
# scanner_tests spawns test_target.exe as its child; run it next to the built
# exes so the relative path resolves under a multi-config generator's Release
# subdir.
add_test(NAME scanner_tests COMMAND scanner_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:scanner_tests>)
