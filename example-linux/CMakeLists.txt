cmake_minimum_required(VERSION 3.10)

project(KittyMemoryExExample)

set(KITTYMEMORY_PATH ../KittyMemoryEx)
FILE(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# https://github.com/keystone-engine/keystone
# get keystone binaries and remove DkNO_KEYSTONE to use MemoryPatch::craeteWithAsm
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Ofast -std=c++20 -DkNO_KEYSTONE")

#link_libraries("-lm -ldl -lpthread")

add_executable(
    KittyMemoryExExample
    example.cpp
    ${KITTYMEMORY_SRC})