#pragma once

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"
#include "KittyMemoryEx.hpp"
#include "KittyMemOp.hpp"
#include "MemoryPatch.hpp"
#include "MemoryBackup.hpp"
#include "KittyScanner.hpp"
#include "KittyTrace.hpp"
#include "KittyArm64.hpp"

using KittyMemoryEx::ProcMap;

struct local_symbol_t
{
    const char *name = nullptr;
    uintptr_t address = 0;

    local_symbol_t() : name(nullptr), address(0) {}
    local_symbol_t(const char *n, uintptr_t a) : name(n), address(a) {}
};

#define KT_LOCAL_SYMBOL(x) local_symbol_t(#x, uintptr_t(x))

class KittyMemoryMgr
{
private:
    bool _init;
    pid_t _pid;
    std::string _process_name;
    EKittyMemOP _eMemOp;
    std::unique_ptr<IKittyMemOp> _pMemOp;
    std::unique_ptr<IKittyMemOp> _pMemOpPatch;

public:
    MemoryPatchMgr memPatch;
    MemoryBackupMgr memBackup;
    KittyScannerMgr memScanner;
    ElfScannerMgr elfScanner;
    KittyTraceMgr trace;

    KittyMemoryMgr() : _init(false), _pid(0), _eMemOp(EK_MEM_OP_NONE) {}

    /**
     * Initialize memory manager
     * @param pid remote process ID
     * @param eMemOp: Memory read & write operation type [ EK_MEM_OP_SYSCALL / EK_MEM_OP_IO ]
     * @param initMemPatch: initialize MmeoryPatch & MemoryBackup instances, pass true if you want to use memPatch & memBackup
     */
    bool initialize(pid_t pid, EKittyMemOP eMemOp, bool initMemPatch);

    inline pid_t processID() const { return _pid; }

    inline std::string processName() const { return _process_name; }

    inline bool isMemValid() const { return _init && _pid && _pMemOp.get(); }

    /**
     * Read remote memory
     */
    size_t readMem(uintptr_t address, void *buffer, size_t len) const;

    /**
     * Write remote memory
     */
    size_t writeMem(uintptr_t address, void *buffer, size_t len) const;

    /**
     * Read string from remote memory
     */
    std::string readMemStr(uintptr_t address, size_t maxLen) const;

    /**
     * Write string to remote memory
     */
    bool writeMemStr(uintptr_t address, std::string str) const;

    /**
     * Validate ELF
     * @param elfBase: ELF start address
     */
    bool isValidELF(uintptr_t elfBase) const;

    /**
     * Find in-memory loaded ELF with name
     */
    ElfScanner getMemElf(const std::string &elfName) const;

    /**
     * Find in-memory loaded ELF with name in zip
     */
    ElfScanner getMemElfInZip(const std::string &zip, const std::string &elfName) const;

    /**
     * /proc/[pid]/exe
     */
    ElfScanner getMemElfExe() const;

    /**
     * Find remote address of local symbol.
     * Use macro KT_LOCAL_SYMBOL.
     * Example findRemoteOfSymbol(KT_LOCAL_SYMBOL(mmap)), to find mmap address in remote process.
    */
    uintptr_t findRemoteOfSymbol(const local_symbol_t &local_sym) const;

    /**
     * Dump remote memory range
     */
    bool dumpMemRange(uintptr_t start, uintptr_t end, const std::string &path) const;

    /**
     * Dump remote memory maped file
     */
    bool dumpMemFile(const std::string &memFile, const std::string &destination) const;

    /**
     * Dump remote memory loaded ELF
     */
    bool dumpMemELF(uintptr_t elfBase, const std::string &destination) const;
};