#pragma once

#include "KittyUtils.hpp"

namespace KittyMemoryEx
{
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
            executable(false), is_private(false), is_shared(false), is_ro(false), is_rw(false), is_rx(false), offset(0),
            inode(0)
      {
      }

    inline bool operator==(const ProcMap& other) const 
    {
        return (pid == other.pid &&
        startAddress == other.startAddress && endAddress == other.endAddress &&
        protection == other.protection && is_private == other.is_private &&
        is_shared == other.is_shared && offset == other.offset && dev == other.dev &&
        inode == other.inode && pathname == other.pathname);
    }

    inline bool operator!=(const ProcMap& other) const 
    {
      return (pid != other.pid ||
      startAddress != other.startAddress || endAddress != other.endAddress ||
      protection != other.protection || is_private != other.is_private ||
      is_shared != other.is_shared || offset != other.offset || dev != other.dev ||
      inode != other.inode || pathname != other.pathname);
    }

    inline bool isValid() const { return (pid && startAddress && endAddress && length); }
    inline bool isUnknown() const { return pathname.empty(); }
    inline bool contains(uintptr_t address) const { return address >= startAddress && address < endAddress; }
    inline std::string toString() const
    {
        return KittyUtils::String::Fmt("%" PRIxPTR "-%" PRIxPTR " %c%c%c%c %" PRIxPTR " %s %lu %s", startAddress,
                                       endAddress, readable ? 'r' : '-', writeable ? 'w' : '-', executable ? 'x' : '-',
                                       is_private ? 'p' : 's', offset, dev.c_str(), inode, pathname.c_str());
    }
  };

  /*
   * reads /proc/[pid]/cmdline
   */
  std::string getProcessName(pid_t pid);

  /*
   * find processes ID by matching /proc/[pid]/cmdline
   */
  std::vector<pid_t> getProcessIDs(const std::string &processName);

  /*
   * find process ID by matching /proc/[pid]/cmdline
   */
  pid_t getProcessID(const std::string &processName);

  /*
   * find process threads ID at /proc/[pid]/task
   */
  std::vector<pid_t> getAllThreads(pid_t pid);

  class ProcStatus
  {
      std::unordered_map<std::string, std::string> data;
      static bool parse(const std::string &path, ProcStatus *out);
      static bool getIntFast(const std::string &path, const std::string &var, int *out);

  public:
      ProcStatus() = default;
      ~ProcStatus()
      {
          data.clear();
      }

      inline static bool parse(pid_t pid, ProcStatus *out)
      {
          if (pid <= 0)
              return false;
          return parse("/proc/" + std::to_string(pid) + "/status", out);
      }

      inline static bool parse(pid_t pid, pid_t tid, ProcStatus *out)
      {
          if (pid <= 0)
              return false;
          return parse("/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/status", out);
      }

      inline bool contains(const std::string &key) const
      {
          return data.find(key) != data.end();
      }

      inline std::string getString(const std::string &key) const
      {
          auto it = data.find(key);
          return (it != data.end()) ? it->second : "";
      }

      inline long long getInt(const std::string &key) const
      {
          auto it = data.find(key);
          if (it == data.end())
              return 0;

          return std::strtoll(it->second.c_str(), nullptr, 10);
      }

      inline bool getBool(const std::string &key) const
      {
          return getInt(key) == 1;
      }

      inline static bool getIntFast(pid_t pid, const std::string &var, int *out)
      {
          if (pid <= 0)
              return false;
          return getIntFast("/proc/" + std::to_string(pid) + "/status", var, out);
      }

      inline static bool getIntFast(pid_t pid, pid_t tid, const std::string &var, int *out)
      {
          if (pid <= 0)
              return false;
          return getIntFast("/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/status", var, out);
      }
  };

  enum class EProcMapFilter
  {
      Equal,
      Contains,
      StartWith,
      EndWith
  };

  /*
   * Gets info of all maps in /proc/[pid]/maps
   */
  std::vector<ProcMap> getAllMaps(pid_t pid);

  /*
   * Gets info of all maps with filter in /proc/[pid]/maps
   */
  std::vector<ProcMap> getMaps(pid_t pid, EProcMapFilter filter, const std::string &name,
                               const std::vector<ProcMap> &maps = std::vector<ProcMap>());

  /*
   * Gets map info of an address in /proc/[pid]/maps
   */
  ProcMap getAddressMap(pid_t pid, uintptr_t address, const std::vector<ProcMap> &maps = std::vector<ProcMap>());

#ifdef __ANDROID__
    std::string getAppDirectory(const std::string &pkg);
  #endif
}
