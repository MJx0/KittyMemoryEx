LOCAL_PATH := $(call my-dir)

KITTYMEMORY_PATH = ../KittyMemoryEx
KITTYMEMORY_SRC = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)

# Disable keystone support
KT_DISABLE_KEYSTONE ?= false

## Keystone static lib link
ifeq ($(KT_DISABLE_KEYSTONE),false)
include $(CLEAR_VARS)
LOCAL_MODULE    := Keystone
LOCAL_SRC_FILES := $(KITTYMEMORY_PATH)/Deps/Keystone/libs-android/$(TARGET_ARCH_ABI)/libkeystone.a
include $(PREBUILT_STATIC_LIBRARY)
endif

## Example exec
include $(CLEAR_VARS)

LOCAL_MODULE := KittyMemoryExample

# add -DkITTYMEMORY_DEBUG for debug outputs
LOCAL_CPPFLAGS += -std=c++17

LOCAL_SRC_FILES := example.cpp $(KITTYMEMORY_SRC)

## add keystone
ifeq ($(KT_DISABLE_KEYSTONE),false)
LOCAL_STATIC_LIBRARIES := Keystone
endif

include $(BUILD_EXECUTABLE)
