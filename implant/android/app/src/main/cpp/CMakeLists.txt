cmake_minimum_required(VERSION 3.22.1)
project(umbra CXX)

add_library(umbra SHARED umbra_jni.cpp)

set_target_properties(umbra PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

target_compile_options(umbra PRIVATE -Os -fvisibility=hidden -fno-exceptions -fno-rtti)
