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
    tui/help.c
    tui/help_books/commands.c
    tui/help_books/processes.c
    tui/help_books/scanner.c
    tui/help_books/address_table.c
    core/process/process.c
    core/memory/memory.c
    core/scanner/scanner.c
    core/address_table/address_table.c
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

add_executable(address_table_tests
    test/address_table_tests.c
    core/address_table/address_table.c
    core/scanner/scanner.c
    core/memory/memory.c
    core/process/process.c
    platform/platform.c
)
target_compile_options(address_table_tests PRIVATE /W4 /WX /wd5105)
target_include_directories(address_table_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(address_table_tests PRIVATE psapi)

add_executable(tui_command_tests
    test/tui_command_tests.c
    tui/commands.c
    tui/helpers.c
    tui/help.c
    tui/help_books/commands.c
    tui/help_books/processes.c
    tui/help_books/scanner.c
    tui/help_books/address_table.c
    core/address_table/address_table.c
    core/scanner/scanner.c
    core/memory/memory.c
    core/process/process.c
    platform/platform.c
)
target_compile_options(tui_command_tests PRIVATE /W4 /WX /wd5105)
target_include_directories(tui_command_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tui_command_tests PRIVATE psapi)

enable_testing()
add_test(NAME core_tests COMMAND core_tests)
# scanner_tests spawns test_target.exe as its child; run it next to the built
# exes so the relative path resolves under a multi-config generator's Release
# subdir.
add_test(NAME scanner_tests COMMAND scanner_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:scanner_tests>)
add_test(NAME address_table_tests COMMAND address_table_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:address_table_tests>)
add_test(NAME tui_command_tests COMMAND tui_command_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:tui_command_tests>)
