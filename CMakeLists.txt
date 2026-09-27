cmake_minimum_required(VERSION 3.16)
project(MemForge LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_library(memforge_core STATIC
    core/process/process.c
    core/memory/memory.c
    core/hexview/hexview.c
    core/disasm/disasm.c
    core/debugger/debugger.c
    core/debugger/events.c
    core/debugger/watch.c
    core/injector/injector.c
    core/pointer_scan/pointer_scan.c
    core/pointer_scan/index.c
    core/structure/structure.c
    core/scanner/scanner.c
    core/address_table/address_table.c
    platform/platform.c
    platform/debugger.c
    platform/injector.c
)

add_library(memforge_zydis STATIC
    vendor/zydis/Zydis.c
)
target_include_directories(memforge_zydis PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/zydis)
target_compile_definitions(memforge_zydis PUBLIC ZYDIS_STATIC_BUILD)

target_include_directories(memforge_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(memforge_core PUBLIC /experimental:c11atomics)
target_link_libraries(memforge_core PUBLIC psapi memforge_zydis)

set(MEMFORGE_TUI_SOURCES
    tui/commands.c
    tui/debugger.c
    tui/injection.c
    tui/pointers.c
    tui/structure.c
    tui/helpers.c
    tui/scan_job.c
    tui/render.c
    tui/help.c
    tui/help_books/commands.c
    tui/help_books/processes.c
    tui/help_books/scanner.c
    tui/help_books/address_table.c
    tui/help_books/hexview.c
    tui/help_books/disasm.c
    tui/help_books/debugger.c
    tui/help_books/tools.c
)
add_executable(memforge tui/main.c tui/tui.c ${MEMFORGE_TUI_SOURCES})
target_link_libraries(memforge PRIVATE memforge_core)

add_executable(test_target
    test_target/main.c
)

add_executable(debugger_target test/debugger_target.c)
add_executable(debugger_tests test/debugger_tests.c)
target_link_libraries(debugger_tests PRIVATE memforge_core)
add_dependencies(debugger_tests debugger_target)

add_library(injector_fixture SHARED test/injector_fixture.c)
add_executable(injector_tests test/injector_tests.c)
target_link_libraries(injector_tests PRIVATE memforge_core)
add_dependencies(injector_tests injector_fixture)
add_executable(pointer_target test/pointer_target.c)
add_executable(pointer_tests test/pointer_tests.c)
target_link_libraries(pointer_tests PRIVATE memforge_core)
add_dependencies(pointer_tests pointer_target)
add_executable(structure_tests test/structure_tests.c)
target_link_libraries(structure_tests PRIVATE memforge_core)
add_executable(core_tests
    test/core_tests.c
)
target_link_libraries(core_tests PRIVATE memforge_core)

add_executable(hexview_tests
    test/hexview_tests.c
)
target_link_libraries(hexview_tests PRIVATE memforge_core)

add_executable(disasm_tests
    test/disasm_tests.c
)
target_link_libraries(disasm_tests PRIVATE memforge_core)

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
    ${MEMFORGE_TUI_SOURCES}
)
target_link_libraries(tui_command_tests PRIVATE memforge_core)

add_executable(tui_runtime_tests
    test/tui_runtime_tests.c
    ${MEMFORGE_TUI_SOURCES}
)
target_link_libraries(tui_runtime_tests PRIVATE memforge_core)

add_executable(tui_console_tests test/tui_console_tests.c)
add_dependencies(tui_console_tests memforge debugger_target injector_fixture)

foreach(target memforge_zydis memforge_core memforge core_tests hexview_tests disasm_tests
               scanner_tests address_table_tests tui_command_tests tui_runtime_tests tui_console_tests
               debugger_target debugger_tests injector_fixture injector_tests pointer_target pointer_tests structure_tests)
    target_compile_options(${target} PRIVATE /W4 /WX /wd5105)
endforeach()
target_compile_options(test_target PRIVATE /W4 /WX)

enable_testing()
add_test(NAME core_tests COMMAND core_tests)
add_test(NAME hexview_tests COMMAND hexview_tests)
add_test(NAME disasm_tests COMMAND disasm_tests)
add_test(NAME debugger_tests COMMAND debugger_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:debugger_tests>)
set_tests_properties(debugger_tests PROPERTIES TIMEOUT 45)
add_test(NAME debugger_terminated_tests COMMAND debugger_tests --terminated-paused
         WORKING_DIRECTORY $<TARGET_FILE_DIR:debugger_tests>)
set_tests_properties(debugger_terminated_tests PROPERTIES TIMEOUT 15)
# scanner_tests spawns test_target.exe as its child; run it next to the built
# exes so the relative path resolves under a multi-config generator's Release
# subdir.
add_test(NAME scanner_tests COMMAND scanner_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:scanner_tests>)
add_test(NAME address_table_tests COMMAND address_table_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:address_table_tests>)
add_test(NAME tui_command_tests COMMAND tui_command_tests
         WORKING_DIRECTORY $<TARGET_FILE_DIR:tui_command_tests>)
add_test(NAME tui_runtime_tests COMMAND tui_runtime_tests)
add_test(NAME tui_console_tests COMMAND tui_console_tests $<TARGET_FILE:memforge>)
set_tests_properties(tui_console_tests PROPERTIES TIMEOUT 40)

add_test(NAME injector_tests COMMAND injector_tests WORKING_DIRECTORY $<TARGET_FILE_DIR:injector_tests>)
add_test(NAME pointer_tests COMMAND pointer_tests WORKING_DIRECTORY $<TARGET_FILE_DIR:pointer_tests>)
add_test(NAME structure_tests COMMAND structure_tests)
set_tests_properties(injector_tests pointer_tests PROPERTIES TIMEOUT 30)
