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

using KittyMemoryEx::EProcMapFilter;
using KittyMemoryEx::ProcMap;
using KittyMemoryEx::ProcStatus;

/**
 * @brief Class that manages memory operations for a remote process.
 */
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
    /// @brief MemoryPatch Manager
    MemoryPatchMgr memPatch;
    /// @brief MemoryBackup Manager
    MemoryBackupMgr memBackup;
    /// @brief Memory Scanner Manager
    KittyScannerMgr memScanner;
    /// @brief Elf Scanner Manager
    ElfScannerMgr elfScanner;

#ifdef __ANDROID__
    /// @brief Linker Scanner Manager
    LinkerScannerMgr linkerScanner;
    /// @brief NativeBridge Scanner Manager
    NativeBridgeScannerMgr nbScanner;
#endif

    /// @brief Process Trace Manager
    KittyTraceMgr trace;

    KittyMemoryMgr() : _init(false), _pid(0), _eMemOp(EK_MEM_OP_NONE)
    {
    }

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
    inline pid_t processID() const
    {
        return _pid;
    }

    /**
     * @brief Returns the process name.
     * @return The name of the remote process.
     */
    inline std::string processName() const
    {
        return _process_name;
    }

    /**
     * @brief Checks if memory operations are valid.
     */
    inline bool isMemValid() const
    {
        return _init && _pid && _pMemOp.get();
    }

    /**
     * @brief Returns memory operations pointer.
     */
    inline IKittyMemOp *memOp() const
    {
        return _pMemOp.get();
    }

    /**
     * @brief Reads remote memory from a specified address.
     * @param address The address in remote memory to read.
     * @param buffer The buffer to store the read data.
     * @param len The number of bytes to read.
     * @return The number of bytes read.
     */
    size_t readMem(uintptr_t address, void *buffer, size_t len) const;

    /**
     * @brief Writes remote memory to a specified address.
     * @param address The address in remote memory to write to.
     * @param buffer The buffer containing the data to write.
     * @param len The number of bytes to write.
     * @return The number of bytes written.
     */
    size_t writeMem(uintptr_t address, void *buffer, size_t len) const;

    /**
     * @brief Reads a string from remote memory.
     * @param address The address in remote memory to read the string from.
     * @param maxLen The maximum length of the string to read.
     * @return The string read from remote memory.
     */
    std::string readMemStr(uintptr_t address, size_t maxLen) const;

    /**
     * @brief Writes a string to remote memory.
     * @param address The address in remote memory to write the string to.
     * @param str The string to write to remote memory.
     * @return True if the string is written successfully, false otherwise.
     */
    bool writeMemStr(uintptr_t address, std::string str) const;

    /**
     * @brief Dumps a memory range to a file.
     * @param start The start address of the memory range to dump.
     * @param end The end address of the memory range to dump.
     * @param path The path to the file where the memory range will be dumped.
     * @return True if the memory range is dumped successfully, false otherwise.
     */
    bool dumpMemRange(uintptr_t start, uintptr_t end, const std::string &path) const;

    /**
     * @brief Dumps a memory mapped file from a remote process.
     * @param memFile The memory file to dump.
     * @param destination The path where the memory file will be dumped.
     * @return True if the memory mapped file is dumped successfully, false otherwise.
     */
    bool dumpMemFile(const std::string &memFile, const std::string &destination) const;

    /**
     * @brief Dumps a memory mapped ELF file from a remote process.
     * @param elf The ELF scanner to use for dumping the ELF file.
     * @param destination The path where the ELF file will be dumped.
     * @return True if the ELF file is dumped successfully, false otherwise.
     */
    bool dumpMemELF(const ElfScanner &elf, const std::string &destination) const;
};