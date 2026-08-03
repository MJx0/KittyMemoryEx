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
     * @param mode Memory access strategy.
     * @return The number of bytes read.
     */
    inline size_t readMem(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal) const
    {
        if (!isMemValid() || !buffer || !len)
            return 0;

        return _pMemOp->Read(address, buffer, len, mode);
    }

    /**
     * @brief Writes remote memory to a specified address.
     * @param address The address in remote memory to write to.
     * @param buffer The buffer containing the data to write.
     * @param len The number of bytes to write.
     * @param mode Memory access strategy.
     * @return The number of bytes written.
     */
    inline size_t writeMem(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal) const
    {
        if (!isMemValid() || !buffer || !len)
            return 0;

        return _pMemOp->Write(address, buffer, len, mode);
    }

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
    std::string readUTF8(uintptr_t address, size_t maxLen)
    {
        if (!isMemValid() || !address || !maxLen)
            return "";

        return _pMemOp->ReadUTF8(address, maxLen);
    }

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
    std::u16string readUTF16(uintptr_t address, size_t maxLen)
    {
        if (!isMemValid() || !address || !maxLen)
            return u"";

        return _pMemOp->ReadUTF16(address, maxLen);
    }

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
    std::u32string readUTF32(uintptr_t address, size_t maxLen)
    {
        if (!isMemValid() || !address || !maxLen)
            return U"";

        return _pMemOp->ReadUTF32(address, maxLen);
    }

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
    std::wstring readWStr(uintptr_t address, size_t maxLen)
    {
        if (!isMemValid() || !address || !maxLen)
            return L"";

        return _pMemOp->ReadWStr(address, maxLen);
    }

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
    inline std::string readMemStr(uintptr_t address, size_t maxLen)
    {
        if (!isMemValid() || !address || !maxLen)
            return "";

        return _pMemOp->ReadStr(address, maxLen);
    }

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
    bool writeMemStr(uintptr_t address, std::string str) const
    {
        if (!isMemValid() || !address || str.empty())
            return false;

        return _pMemOp->WriteStr(address, str);
    }

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
    inline bool writeMemWStr(uintptr_t address, std::wstring str)
    {
        if (!isMemValid() || !address || str.empty())
            return false;

        return _pMemOp->WriteWStr(address, str);
    }

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