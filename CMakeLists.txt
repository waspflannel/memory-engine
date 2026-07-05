cmake_minimum_required(VERSION 3.16)
project(MemForge LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# We use ISO C string functions (e.g. wcsncpy) in the core rather than MSVC's
# non-portable _s variants. MSVC flags those as C4996 "deprecated"; with /WX that
# becomes a hard error. Turn off that specific nag — it is not a real defect.
add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

add_executable(memforge
    tui/main.c
    tui/tui.c
    core/process/process.c
    core/memory/memory.c
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
    platform/platform.c
)
target_compile_options(core_tests PRIVATE /W4 /WX)
target_include_directories(core_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(core_tests PRIVATE psapi)

enable_testing()
add_test(NAME core_tests COMMAND core_tests)
