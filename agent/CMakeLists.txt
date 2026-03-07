cmake_minimum_required(VERSION 3.18)
project(art_jit_tracer LANGUAGES CXX)

add_library(art_jit_tracer SHARED
    src/agent.cpp
    src/debugger.cpp
    src/protocol.cpp
)

target_include_directories(art_jit_tracer PRIVATE include)

# Android log library for __android_log_print
target_link_libraries(art_jit_tracer log)

set_target_properties(art_jit_tracer PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    PREFIX "lib"
)
