cmake_minimum_required(VERSION 3.18)
project(dexbgd-inject C)

add_executable(dexbgd-inject src/inject.c)

target_compile_options(dexbgd-inject PRIVATE -Wall -Wextra -O2)

# libdl is needed for dlsym / dladdr
target_link_libraries(dexbgd-inject dl)
