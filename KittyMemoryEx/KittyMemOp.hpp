#pragma once

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"

/**
 * @brief Enumeration for different types of memory operations.
 */
enum EKittyMemOP
{
    EK_MEM_OP_NONE = 0,
    EK_MEM_OP_SYSCALL,
    EK_MEM_OP_IO
};

/**
 * @brief Memory access strategy.
 *
 * Controls how memory read/write operations behave when encountering
 * inaccessible memory regions.
 */
enum class MemMode
{
    /**
     * @brief Perform a single continuous memory operation.
     *
     * The operation stops when the kernel reports an error or a partial
     * transfer occurs.
     */
    Normal,


    /**
     * @brief Continue operation while skipping inaccessible pages.
     *
     * The implementation will fall back to page-by-page access after a
     * failed continuous operation. Pages that cannot be accessed are skipped.
     */
    SkipInaccessiblePages
};

/**
 * @brief Interface class for memory operations.
 */
class IKittyMemOp
{
protected:
    pid_t _pid;
    int _lastErrno;

public:
    IKittyMemOp() : _pid(0)
    {
    }
    virtual ~IKittyMemOp() = default;

    /**
     * @brief Initializes the memory operations for a given process.
     * @param pid process ID.
     * @return True if initialization is successful, false otherwise.
     */
    virtual bool init(pid_t pid) = 0;

    /**
     * @brief Returns the process ID.
     */
    inline pid_t processID() const
    {
        return _pid;
    }

    /**
     * @brief Reads data from process memory.
     *
     * @param address Memory address to read from.
     * @param buffer Destination buffer.
     * @param len Number of bytes to read.
     * @param mode Memory access strategy.
     *
     * @return Number of bytes successfully read.
     */
    virtual size_t Read(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal) = 0;

    /**
     * @brief Writes data to process memory.
     *
     * @param address Memory address to write to.
     * @param buffer Source buffer containing data.
     * @param len Number of bytes to write.
     * @param mode Memory access strategy.
     *
     * @return Number of bytes successfully written.
     */
    virtual size_t Write(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal) = 0;

    /**
     * @brief Returns the last error number.
     */
    inline int lastErrno() const
    {
        return _lastErrno;
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
    std::string ReadUTF8(uintptr_t address, size_t maxLen);

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
    std::u16string ReadUTF16(uintptr_t address, size_t maxLen);

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
    std::u32string ReadUTF32(uintptr_t address, size_t maxLen);

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
    std::wstring ReadWStr(uintptr_t address, size_t maxLen)
    {
        if constexpr (sizeof(wchar_t) == 2)
        {
            auto str = ReadUTF16(address, maxLen * sizeof(wchar_t));
            return std::wstring(reinterpret_cast<const wchar_t *>(str.data()), str.size());
        }
        else
        {
            auto str = ReadUTF32(address, maxLen * sizeof(wchar_t));
            return std::wstring(reinterpret_cast<const wchar_t *>(str.data()), str.size());
        }
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
    inline std::string ReadStr(uintptr_t address, size_t maxLen)
    {
        return ReadUTF8(address, maxLen);
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
    inline bool WriteStr(uintptr_t address, std::string str)
    {
        const size_t len = str.size() + 1;
        return Write(address, &str[0], len) == len;
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
    inline bool WriteWStr(uintptr_t address, std::wstring str)
    {
        const size_t len = (str.size() + 1) * sizeof(wchar_t);
        return Write(address, &str[0], len) == len;
    }
};

/**
 * @brief Interface class for syscall memory operations.
 */
class KittyMemSys : public IKittyMemOp
{
public:
    /**
     * @brief Initializes the memory operations for a given process.
     * @param pid process ID.
     * @return True if initialization is successful, false otherwise.
     */
    bool init(pid_t pid);

    /**
     * @brief Reads memory using process_vm_readv.
     *
     * @param address Remote process address.
     * @param buffer Destination buffer.
     * @param len Number of bytes to read.
     * @param mode Memory access strategy.
     *
     * @return Number of bytes successfully read.
     */
    size_t Read(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal);

    /**
     * @brief Writes memory using process_vm_writev.
     *
     * @param address Remote process address.
     * @param buffer Source buffer.
     * @param len Number of bytes to write.
     * @param mode Memory access strategy.
     *
     * @return Number of bytes successfully written.
     */
    size_t Write(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal);
};

/**
 * @brief Interface class for IO memory operations.
 */
class KittyMemIO : public IKittyMemOp
{
private:
    std::unique_ptr<KittyIOFile> _pMem;

public:
    /**
     * @brief Initializes the memory operations for a given process.
     * @param pid process ID.
     * @return True if initialization is successful, false otherwise.
     */
    bool init(pid_t pid);

    /**
     * @brief Reads memory through /proc/<pid>/mem.
     *
     * @param address Remote process address.
     * @param buffer Destination buffer.
     * @param len Number of bytes to read.
     * @param mode Memory access strategy.
     *
     * @return Number of bytes successfully read.
     */
    size_t Read(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal);


    /**
     * @brief Writes memory through /proc/<pid>/mem.
     *
     * @param address Remote process address.
     * @param buffer Source buffer.
     * @param len Number of bytes to write.
     * @param mode Memory access strategy.
     *
     * @return Number of bytes successfully written.
     */
    size_t Write(uintptr_t address, void *buffer, size_t len, MemMode mode = MemMode::Normal);
};