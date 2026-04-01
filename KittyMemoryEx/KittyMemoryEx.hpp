#pragma once

#include "KittyUtils.hpp"
#include <unordered_map>

/**
 * @brief Provides utility functions for process memory.
 */
namespace KittyMemoryEx
{
    /**
     * @brief Represents a mapping of a memory region.
     */
    class ProcMap
    {
    public:
        pid_t pid;
        uintptr_t startAddress;
        uintptr_t endAddress;
        size_t length;
        int protection;
        bool readable, writeable, executable;
        bool is_private, is_shared;
        bool is_ro, is_rw, is_rx;
        uintptr_t offset;
        std::string dev;
        unsigned long inode;
        std::string pathname;

        ProcMap()
            : pid(0), startAddress(0), endAddress(0), length(0), protection(0), readable(false), writeable(false),
              executable(false), is_private(false), is_shared(false), is_ro(false), is_rw(false), is_rx(false),
              offset(0), inode(0)
        {
        }

        inline bool operator==(const ProcMap &other) const
        {
            return (pid == other.pid && startAddress == other.startAddress && endAddress == other.endAddress &&
                    protection == other.protection && is_private == other.is_private && is_shared == other.is_shared &&
                    offset == other.offset && dev == other.dev && inode == other.inode && pathname == other.pathname);
        }

        inline bool operator!=(const ProcMap &other) const
        {
            return (pid != other.pid || startAddress != other.startAddress || endAddress != other.endAddress ||
                    protection != other.protection || is_private != other.is_private || is_shared != other.is_shared ||
                    offset != other.offset || dev != other.dev || inode != other.inode || pathname != other.pathname);
        }

        /**
         * @brief Checks if the map is valid.
         */
        inline bool isValid() const
        {
            return (startAddress && endAddress && length);
        }

        /**
         * @brief Checks if the map is unknown (i.e., no pathname).
         */
        inline bool isUnknown() const
        {
            return pathname.empty();
        }

        /**
         * @brief Checks if the map contains a specific address.
         *
         * @param address Address to check.
         * @return True if the address is within the map, false otherwise.
         */
        inline bool contains(uintptr_t address) const
        {
            return address >= startAddress && address < endAddress;
        }

        /**
         * @brief Converts the map to a string representation..
         */
        inline std::string toString() const
        {
            return KittyUtils::String::fmt("%" PRIxPTR "-%" PRIxPTR " %c%c%c%c %" PRIxPTR " %s %lu %s",
                                           startAddress,
                                           endAddress,
                                           readable ? 'r' : '-',
                                           writeable ? 'w' : '-',
                                           executable ? 'x' : '-',
                                           is_private ? 'p' : 's',
                                           offset,
                                           dev.c_str(),
                                           inode,
                                           pathname.c_str());
        }
    };

    /**
     * @brief Retrieves the name of the process by its process ID.
     *
     * This function reads the command line of the process identified by the given process ID and returns
     * the process name.
     *
     * @param pid The process ID of the process.
     * @return The name of the process.
     */
    std::string getProcessName(pid_t pid);

    /**
     * @brief Retrieves a list of process IDs that match a given process name.
     *
     * This function searches for all processes whose command line matches the specified process name
     * and returns their process IDs in a vector.
     *
     * @param processName The name of the process to match.
     * @return A vector of process IDs that match the specified process name.
     */
    std::vector<pid_t> getProcessIDs(const std::string &processName);

    /**
     * @brief Retrieves the process ID that matches a given process name.
     *
     * This function searches for the first process whose command line matches the specified process name
     * and returns its process ID.
     *
     * @param processName The name of the process to match.
     * @return The process ID that matches the specified process name.
     */
    pid_t getProcessID(const std::string &processName);

    /**
     * @brief Retrieves a list of thread IDs for a given process ID.
     *
     * This function retrieves the thread IDs of all threads associated with the specified process ID
     * by examining the `/proc/[pid]/task` directory.
     *
     * @param pid The process ID of the process.
     * @return A vector of thread IDs for the specified process.
     */
    std::vector<pid_t> getAllThreads(pid_t pid);

    /**
     * @brief Class to retrieve process status information.
     */
    class ProcStatus
    {
        pid_t _pid, _tid;
        std::unordered_map<std::string, std::string> data;
        static bool parse(const std::string &path, ProcStatus *out);

    public:
        ProcStatus() : _pid(-1), _tid(-1)
        {
        }
        ~ProcStatus()
        {
            data.clear();
        }

        /**
         * @brief Parses the status of a process given its PID.
         *
         * @param pid The PID of the process to parse.
         * @param out A pointer to the ProcStatus object where the parsed data will be stored.
         * @return True if parsing was successful, false otherwise.
         */
        inline static bool parse(pid_t pid, ProcStatus *out)
        {
            if (pid <= 0 || !out)
                return false;

            out->_pid = pid;
            return parse("/proc/" + std::to_string(pid) + "/status", out);
        }

        /**
         * @brief Parses the status of a process given its PID and thread ID.
         *
         * @param pid The PID of the process.
         * @param tid The thread ID of the process.
         * @param out A pointer to the ProcStatus object where the parsed data will be stored.
         * @return True if parsing was successful, false otherwise.
         */
        inline static bool parse(pid_t pid, pid_t tid, ProcStatus *out)
        {
            if (pid <= 0 || tid <= 0 || !out)
                return false;

            out->_pid = pid;
            out->_tid = tid;
            return parse("/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/status", out);
        }

        /**
         * @brief Refreshes the process status.
         *
         * If the tid is less than or equal to 0, it calls the parse function with the pid.
         * If the tid is greater than 0, it calls the parse function with the pid and tid.
         *
         * @return True if refreshing was successful, false otherwise.
         */
        inline bool refresh()
        {
            return _tid <= 0 ? parse(_pid, this) : parse(_pid, _tid, this);
        }

        /**
         * @brief Checks if the process status data contains a specific key.
         *
         * @param key The key to check.
         * @return True if the key exists, false otherwise.
         */
        inline bool contains(const std::string &key) const
        {
            return data.find(key) != data.end();
        }

        /**
         * @brief Retrieves the string value associated with a key.
         *
         * @param key The key to retrieve.
         * @return The string value associated with the key, or an empty string if the key is not found.
         */
        inline std::string getString(const std::string &key) const
        {
            auto it = data.find(key);
            return (it != data.end()) ? it->second : "";
        }

        /**
         * @brief Retrieves the integer value associated with a key.
         *
         * @param key The key to retrieve.
         * @return The integer value associated with the key, or 0 if the key is not found.
         */
        inline long long getInt(const std::string &key) const
        {
            auto it = data.find(key);
            if (it == data.end())
                return 0;

            return std::strtoll(it->second.c_str(), nullptr, 10);
        }

        /**
         * @brief Retrieves the boolean value associated with a key.
         *
         * @param key The key to retrieve.
         * @return True if the key's value is 1, false otherwise.
         */
        inline bool getBool(const std::string &key) const
        {
            return getInt(key) == 1;
        }
    };

    /**
     * @brief Enumerates the filter types for finding memory maps.
     */
    enum class EProcMapFilter
    {
        Equal,
        Contains,
        StartWith,
        EndWith,
        Regex
    };

    /**
     * @brief Retrieves information about all memory maps in a remote process.
     *
     * @param pid The remote process ID
     * @return Vector of ProcMap objects representing all memory maps.
     */
    std::vector<ProcMap> getAllMaps(pid_t pid);

    /**
     * @brief Retrieves information about all memory maps in a remote process.
     *
     * @param pid The remote process ID
     * @param filter Filter type to use.
     * @param name Name to filter by.
     * @param maps The vector of cached process maps (optional).
     * @return Vector of ProcMap objects that match the filter.
     */
    std::vector<ProcMap> getMaps(pid_t pid,
                                 EProcMapFilter filter,
                                 const std::string &name,
                                 const std::vector<ProcMap> &maps = std::vector<ProcMap>());

    /**
     * @brief Retrieves the map information for a specific address in the current process.
     *
     * @param pid The remote process ID
     * @param address Address to search for.
     * @param maps The vector of cached process maps (optional).
     * @return ProcMap object representing the map for the address, or an invalid map if not found.
     */
    ProcMap getAddressMap(pid_t pid, uintptr_t address, const std::vector<ProcMap> &maps = std::vector<ProcMap>());

#ifdef __ANDROID__
    /**
     * @brief Retrieves the Android app directory.
     *
     * @param pkg The app's package name
     * @return App directory
     */
    std::string getAppDirectory(const std::string &pkg);
#endif
} // namespace KittyMemoryEx
