# KittyMemoryEx

External implementation of [KittyMemory](https://github.com/MJx0/KittyMemory).

Dedicated library for runtime code patching, memory scanning, tracing, injection and some more useful memory utilities. works for both Android and Linux

KittyMemoryEx depends on [Keystone Assembler](https://github.com/keystone-engine/keystone) for MemoryPatch::createWithAsm.

Prebuilt Keystone binaries for android are already included [Here](KittyMemoryEx/Deps/Keystone/), However if you want to build them yourself you can use the scripts [build-android.sh](Deps/keystone-build-android.sh).

If for any reason you don't want to use Keystone and MemoryPatch::createWithAsm then add definition kNO_KEYSTONE to your project cpp flags.

[Android project example](example-android/README.md), [Linux project example](example-linux/README.md) for how to use & build.

<h2> Features: </h2>

- Two types of remote memory read & write (IO and Syscall)
- Memory patch (bytes, hex and asm)
- Memory scan
- ELF scanner
- ELF symbol lookup
- ptrace utilities
- Setting hard & soft breakpoints
- Memory dump
- Linker & NativeBridge scanner for android

## Documentation

[![Android API Docs](https://img.shields.io/badge/Android-Doxygen-green?style=for-the-badge&logo=android)](https://MJx0.github.io/KittyMemoryEx/android/index.html)

[![Linux API Docs](https://img.shields.io/badge/Linux-Doxygen-blue?style=for-the-badge&logo=linux)](https://MJx0.github.io/KittyMemoryEx/linux/index.html)
