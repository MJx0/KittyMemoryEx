cmake_minimum_required(VERSION 3.5)

project(KittyMemoryExExample)

set(KITTYMEMORYEX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../KittyMemoryEx)
file(GLOB KITTYMEMORYEX_SRC ${KITTYMEMORYEX_PATH}/*.cpp)
set(KEYSTONE_LIB ${KITTYMEMORYEX_PATH}/Deps/Keystone/libs-android/${CMAKE_ANDROID_ARCH_ABI}/libkeystone.a)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument -O0 -g -std=c++20 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument -O2 -s -std=c++20 -DNDEBUG")

add_library(KittyMemoryExExample SHARED example.cpp ${KITTYMEMORYEX_SRC})

target_include_directories(KittyMemoryExExample PUBLIC ${KITTYMEMORYEX_PATH})
target_link_libraries(KittyMemoryExExample -llog ${KEYSTONE_LIB})