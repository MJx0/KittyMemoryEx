# KittyMemoryEx

KittyMemoryEx is the external implementation of [KittyMemory](https://github.com/MJx0/KittyMemory): the same memory patching, scanning, dumping, ELF introspection toolkit, but for remote processes on **Android** and **Linux**. It adds remote memory I/O, ptrace-based process control, hardware/software breakpoints, remote function/syscall calls. It is the memory backend used by [AndKittyInjector](https://github.com/MJx0/AndKittyInjector).

## Features

- **Two remote memory backends**, selected per `KittyMemoryMgr::initialize()` call:
  - `EK_MEM_OP_SYSCALL` — `process_vm_readv` / `process_vm_writev`.
  - `EK_MEM_OP_IO` — `/proc/<pid>/mem` via `pread`/`pwrite` (also used transparently for patching even when the primary backend is `EK_MEM_OP_SYSCALL`, since patch writes to non-writable text pages need `/proc/pid/mem` semantics).
- **Memory patch & backup that work on remote processes** — `MemoryPatch`/`MemoryBackup`, built from raw bytes, hex, or Keystone-assembled instructions, exactly like KittyMemory but bound to an `IKittyMemOp*` instead of the local process.
- **Pattern scanning** — the same four search modes as KittyMemory (bytes+mask, hex+mask, IDA pattern, raw data), streamed through the target process in 1 MiB chunks that skip unmapped pages.
- **ELF scanner & symbol lookup** — `ElfScannerMgr::findElf`, `findSymbolAll` (locate a library across every mapped ELF in the target, even if renamed), and `findRemoteSymbol` (resolve a symbol you already have the address of locally, e.g. `mmap`, to its equivalent address in the target process — the basis for remote function calls).
- **ptrace utilities (`KittyTraceMgr`)** — attach (`PTRACE_ATTACH`) or seize (`PTRACE_SEIZE`), stop/continue/single-step, register get/set, and:
  - **Remote function/syscall calls** — `callFunction`, `callFunctionFrom`, `callSyscall`, ABI-aware per architecture (arm/arm64/x86/x86_64).
  - **Hardware & software breakpoints** — `setHardBreakpointAndWait` (debug registers — execute/read/write/access, no code patching) and `setSoftBreakpointAndWait` (trap-instruction patching), both blocking-with-callback and re-armable.
- **`KittyPerfWatch` / `KittyPerfTrap`** — `perf_event_open`-based hardware watchpoints as a pollable/signal-driven alternative to ptrace single-stepping.
- **Android linker & NativeBridge scanners** — enumerate every natively-loaded (`LinkerScannerMgr`) or emulated (`NativeBridgeScannerMgr`) library by walking the linker's internal `solist`.
- **Memory maps**
  - `KittyMemoryEx::ProcMap` models one `/proc/<pid>/maps` entry of the *target* process (bounds, permissions, backing file).
  - `getAllMaps(pid)` / `getMaps(pid, EProcMapFilter, name)` (`Equal`/`Contains`/`StartWith`/`EndWith`/`Regex`) / `getAddressMap(pid, address)` enumerate and filter memory maps.
  - `getFileMappings(pid, path)` groups a backing file's mappings into contiguous runs, same semantics as KittyMemory.
  - `ProcStatus` parses `/proc/<pid>/status` (or a specific thread's) into key/value pairs — used to check `TracerPid` before attaching.
- **Memory, file-mapping & ELF dump utilities**
  - `KittyMemoryMgr::dumpMemRange` dumps an arbitrary remote address range to a file.
  - `dumpMemFileMappings` locates and dumps every contiguous mapping of a memory-mapped file in the target (e.g. `global-metadata.dat`), even when split across multiple mappings.
  - `dumpMemELF` writes a loaded remote ELF to disk.
- **`KittyUtils` Various utilities**.

## Requirements

- C++17 or newer.
- Android: NDK, API level 21 or newer.
- iOS: [Theos](https://theos.dev/) or xcode for building tweaks/dylibs, deployment target iOS 14.0+.
- [Keystone Assembler](https://github.com/keystone-engine/keystone) — only needed for `MemoryPatch::createWithAsm`. Prebuilt static libraries for android already vendored under [`KittyMemory/Deps/Keystone`](KittyMemory/Deps/Keystone/); You can rebuild them yourself with `Deps/Keystone/build_keystone_android.sh` / `build_keystone_linux.sh`. If you don't want Keystone dependency then Define `kNO_KEYSTONE` in your project's C++ flags (this removes `createWithAsm`).
- **Root / ptrace considerations**: reading or writing another process's memory (via `process_vm_readv/writev`, `/proc/pid/mem`, or `ptrace`) requires matching UID/ptrace scope permissions or root.

See [example-android/README.md](example-android/README.md) and [example-linux/README.md](example-linux/README.md) for full build steps.

## Usage

`KittyMemoryMgr`:

```cpp
class KittyMemoryMgr {
public:
    MemoryPatchMgr    memPatch;     // patch/restore remote memory
    MemoryBackupMgr   memBackup;    // snapshot/restore remote memory
    KittyScannerMgr   memScanner;   // pattern scanning
    ElfScannerMgr     elfScanner;   // ELF parsing & symbol lookup
#ifdef __ANDROID__
    LinkerScannerMgr       linkerScanner; // Android dynamic linker scanner
    NativeBridgeScannerMgr nbScanner;     // emulated Android dynamic linker scanner
#endif
    KittyTraceMgr     trace;        // ptrace attach/detach, breakpoints, remote calls

    /**
     * @brief Initializes the memory manager.
     * @param pid Remote process ID.
     * @param eMemOp Memory read & write operation type.
     * @param initMemPatch If true, initializes MemoryPatch and MemoryBackup instances.
     * @return True if initialization is successful, false otherwise.
     */
    bool initialize(pid_t pid, EKittyMemOP eMemOp, bool initMemPatch);

    /**
     * @brief Returns the process ID.
     */
    pid_t processID() const;

    /**
     * @brief Returns the process name.
     * @return The name of the remote process.
     */
    std::string processName() const;

    /**
     * @brief Checks if memory operations are valid.
     */
    bool isMemValid() const;

    /**
     * @brief Returns memory operations pointer.
     */
    IKittyMemOp *memOp() const;

    /**
     * @brief Reads remote memory from a specified address.
     * @param address The address in remote memory to read.
     * @param buffer The buffer to store the read data.
     * @param len The number of bytes to read.
     * @param mode Memory access strategy.
     * @return The number of bytes read.
     */
    size_t readMem(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal) const;

    /**
     * @brief Writes remote memory to a specified address.
     * @param address The address in remote memory to write to.
     * @param buffer The buffer containing the data to write.
     * @param len The number of bytes to write.
     * @param mode Memory access strategy.
     * @return The number of bytes written.
     */
    size_t writeMem(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal) const;

    /**
     * @brief Reads a UTF-8 encoded string from remote process memory.
     *
     * Reads at most @p maxLen bytes starting at @p address and stops when the
     * first null terminator is encountered.
     *
     * @param address Remote memory address containing the string.
     * @param maxLen Maximum number of bytes to read.
     *
     * @return UTF-8 string stored in remote memory.
     */
    std::string readUTF8(uintptr_t address, size_t maxLen);
    /**
     * @brief Reads a UTF-16 encoded string from remote process memory.
     *
     * Reads at most @p maxLen bytes and stops at the first UTF-16 null terminator.
     *
     * @param address Remote memory address containing the string.
     * @param maxLen Maximum number of bytes to read.
     *
     * @return UTF-16 string stored in remote memory.
     */
    std::u16string readUTF16(uintptr_t address, size_t maxLen);

    /**
     * @brief Reads a UTF-32 encoded string from remote process memory.
     *
     * Reads at most @p maxLen bytes and stops at the first UTF-32 null terminator.
     *
     * @param address Remote memory address containing the string.
     * @param maxLen Maximum number of bytes to read.
     *
     * @return UTF-32 string stored in remote memory.
     */
    std::u32string readUTF32(uintptr_t address, size_t maxLen);

    /**
     * @brief Reads a platform wchar_t string from remote process memory.
     *
     * Automatically selects the encoding based on the size of wchar_t:
     *
     * @param address Remote memory address containing the string.
     * @param maxLen Maximum number of wchar_t characters to read.
     *
     * @return Wide string stored in remote memory.
     */
    std::wstring readWStr(uintptr_t address, size_t maxLen);

    /**
     * @brief Reads a UTF-8 string from remote process memory.
     *
     * Convenience wrapper around ReadUTF8().
     *
     * @param address Remote memory address containing the string.
     * @param maxLen Maximum number of bytes to read.
     *
     * @return UTF-8 string stored in remote memory.
     */
    std::string readMemStr(uintptr_t address, size_t maxLen);

    /**
     * @brief Writes a UTF-8 string to remote process memory.
     *
     * Writes the string contents followed by a null terminator.
     *
     * @param address Remote memory address where the string is written.
     * @param str UTF-8 string to write.
     *
     * @return true if all bytes were written successfully.
     */
    bool writeMemStr(uintptr_t address, std::string str) const;

    /**
     * @brief Writes a platform wchar_t string to remote process memory.
     *
     * Automatically selects the encoding based on the size of wchar_t:
     *
     * @param address Remote memory address where the string is written.
     * @param str Wide string to write.
     *
     * @return true if all characters and the null terminator were written.
     */
    bool writeMemWStr(uintptr_t address, std::wstring str);

    /**
     * @brief Dumps a memory range from remote process to a file.
     *
     * @param start The start address of the memory range to dump.
     * @param end The end address of the memory range to dump.
     * @param path The path to the file where the memory range will be dumped.
     * @return True if the memory range is dumped successfully, false otherwise.
     */
    bool dumpMemRange(uintptr_t start, uintptr_t end, const std::string &path) const;

    /**
     * @brief Dumps all mappings of a mapped file from a remote process.
     *
     * If the file has multiple mappings, each mapping is written to a separate
     * output file by appending an index to the destination filename.
     *
     * @param memFile Path of the mapped file to dump.
     * @param destination Destination file or directory path.
     * @return True if at least one mapping was successfully dumped, false otherwise.
     */
    bool dumpMemFileMappings(const std::string &memFile, const std::string &destination) const;

    /**
     * @brief Dumps a memory mapped ELF file from a remote process.
     * @param elf The ELF scanner to use for dumping the ELF file.
     * @param destination The path where the ELF file will be dumped.
     * @return True if the ELF file is dumped successfully, false otherwise.
     */
    bool dumpMemELF(const ElfScanner &elf, const std::string &destination) const;
};
```

## Documentation

[![Android API Docs](https://img.shields.io/badge/Android-Doxygen-green?style=for-the-badge&logo=android)](https://MJx0.github.io/KittyMemoryEx/android/index.html)

[![Linux API Docs](https://img.shields.io/badge/Linux-Doxygen-blue?style=for-the-badge&logo=linux)](https://MJx0.github.io/KittyMemoryEx/linux/index.html)
