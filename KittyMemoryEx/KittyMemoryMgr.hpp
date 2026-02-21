#pragma once

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"
#include "KittyMemoryEx.hpp"
#include "KittyMemOp.hpp"
#include "MemoryPatch.hpp"
#include "MemoryBackup.hpp"
#include "KittyScanner.hpp"
#include "KittyTrace.hpp"
#include "KittyAsm.hpp"
#include "KittyPtrValidator.hpp"
#include "KittyPerfEvent.hpp"

using KittyMemoryEx::ProcStatus;
using KittyMemoryEx::ProcMap;
using KittyMemoryEx::EProcMapFilter;

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

#ifdef __ANDROID__
    LinkerScannerMgr linkerScanner;
    NativeBridgeScannerMgr nbScanner;
#endif

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
    bool dumpMemELF(const ElfScanner &elf, const std::string &destination) const;
};