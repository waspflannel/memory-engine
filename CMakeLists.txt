cmake_minimum_required(VERSION 3.16)
project(MemForge LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_library(memforge_core STATIC
    core/process/process.c
    core/memory/memory.c
    core/hexview/hexview.c
    core/scanner/scanner.c
    core/address_table/address_table.c
    platform/platform.c
)

target_include_directories(memforge_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(memforge_core PUBLIC psapi)

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
    tui/help_books/hexview.c
)
target_link_libraries(memforge PRIVATE memforge_core)

add_executable(test_target
    test_target/main.c
)

add_executable(core_tests
    test/core_tests.c
)
target_link_libraries(core_tests PRIVATE memforge_core)

add_executable(hexview_tests
    test/hexview_tests.c
)
target_link_libraries(hexview_tests PRIVATE memforge_core)

add_executable(scanner_tests
    test/scanner_tests.c
)
target_link_libraries(scanner_tests PRIVATE memforge_core)

add_executable(address_table_tests
    test/address_table_tests.c
)
target_link_libraries(address_table_tests PRIVATE memforge_core)

add_executable(tui_command_tests
    test/tui_command_tests.c
    tui/commands.c
    tui/helpers.c
    tui/help.c
    tui/help_books/commands.c
    tui/help_books/processes.c
    tui/help_books/scanner.c
    tui/help_books/address_table.c
    tui/help_books/hexview.c
)
target_link_libraries(tui_command_tests PRIVATE memforge_core)

foreach(target memforge_core memforge core_tests hexview_tests scanner_tests
               address_table_tests tui_command_tests)
    target_compile_options(${target} PRIVATE /W4 /WX /wd5105)
endforeach()
target_compile_options(test_target PRIVATE /W4 /WX)

enable_testing()
add_test(NAME core_tests COMMAND core_tests)
add_test(NAME hexview_tests COMMAND hexview_tests)
# scanner_tests spawns test_target.exe as its child; run it next to the built
# exes so the relative path resolves under a multi-config generator's Release
# subdir.
add_test(NAME scanner_tests COMMAND scanner_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:scanner_tests>)
add_test(NAME address_table_tests COMMAND address_table_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:address_table_tests>)
add_test(NAME tui_command_tests COMMAND tui_command_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:tui_command_tests>)
