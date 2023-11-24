# KittyMemoryEx Android Example

<h3>This is an Android executable example.</h3>

Requires C++11 or above.</br>
Android API 21 or above for keystone linking.

See how to use KittyMemoryEx in [example.cpp](example.cpp).

<h3>Clone:</h3>

```
git clone --recursive https://github.com/MJx0/KittyMemoryEx.git
```

<h3>How to build:</h3>

<h4>NDK Build:</h4>

- In your Android.mk somewhere at top, define:

```make
KITTYMEMORYEX_PATH = path/to/KittyMemoryEx
KITTYMEMORYEX_SRC = $(wildcard $(KITTYMEMORYEX_PATH)/*.cpp)
```

- Inlcude Keystone static lib:

```make
include $(CLEAR_VARS)
LOCAL_MODULE    := Keystone
LOCAL_SRC_FILES := $(KITTYMEMORYEX_PATH)/Deps/Keystone/libs-android/$(TARGET_ARCH_ABI)/libkeystone.a
include $(PREBUILT_STATIC_LIBRARY)
```

- Add KittyMemoryEx source files:

```make
LOCAL_SRC_FILES := example.cpp $(KITTYMEMORYEX_SRC)
```

- Finally add keystone static lib:

```make
LOCAL_STATIC_LIBRARIES := Keystone
```

You can check example here [Android.mk](Android.mk).

<h4>CMake Build:</h4>

- In your CMakeLists.txt somewhere at top, define:

```cmake
set(KITTYMEMORYEX_PATH path/to/KittyMemoryEx)
file(GLOB KITTYMEMORYEX_SRC ${KITTYMEMORYEX_PATH}/*.cpp)
```

- Inlcude Keystone static lib:

```cmake
set(KEYSTONE_LIB ${KITTYMEMORYEX_PATH}/Deps/Keystone/libs-android/${CMAKE_ANDROID_ARCH_ABI}/libkeystone.a)
```

- Add KittyMemoryEx source files:

```cmake
add_library(YourProjectName SHARED example.cpp ${KITTYMEMORYEX_SRC})
```

- Finally add keystone static lib:

```cmake
target_link_libraries(YourProjectName ${KEYSTONE_LIB})
## or
link_libraries(${KEYSTONE_LIB})
```

You can check example here [CMakeLists.txt](CMakeLists.txt).
