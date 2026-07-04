cmake_minimum_required(VERSION 3.16)
project(MemForge LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

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
