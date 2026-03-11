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
     * @brief Reads data from memory.
     * @param address Memory address to read from.
     * @param buffer Buffer to store the read data.
     * @param len Length of data to read.
     * @return Number of bytes read.
     */
    virtual size_t Read(uintptr_t address, void *buffer, size_t len) = 0;

    /**
     * @brief Writes data to memory.
     * @param address Memory address to write to.
     * @param buffer Buffer containing the data to write.
     * @param len Length of data to write.
     * @return Number of bytes written.
     */
    virtual size_t Write(uintptr_t address, void *buffer, size_t len) = 0;

    /**
     * @brief Reads a string from memory.
     * @param address Memory address to read from.
     * @param maxLen Maximum length of the string to read.
     * @return The string read from memory.
     */
    std::string ReadStr(uintptr_t address, size_t maxLen);

    /**
     * @brief Writes a string to memory.
     * @param address Memory address to write to.
     * @param str String to write.
     * @return True if writing is successful, false otherwise.
     */
    bool WriteStr(uintptr_t address, std::string str);

    /**
     * @brief Returns the last error number.
     */
    inline int lastErrno() const
    {
        return _lastErrno;
    }
};

/**
 * @brief Interface class for syscall memory operations.
 */
class KittyMemSys : public IKittyMemOp
{
public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len);
    size_t Write(uintptr_t address, void *buffer, size_t len);
};

/**
 * @brief Interface class for IO memory operations.
 */
class KittyMemIO : public IKittyMemOp
{
private:
    std::unique_ptr<KittyIOFile> _pMem;

public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len);
    size_t Write(uintptr_t address, void *buffer, size_t len);
};