#pragma once

#include "KittyUtils.hpp"

namespace KittyMemoryEx
{
  class ProcMap
  {
  public:
    pid_t pid;
    unsigned long long startAddress;
    unsigned long long endAddress;
    size_t length;
    int protection;
    bool readable, writeable, executable;
    bool is_private, is_shared;
    bool is_ro, is_rw, is_rx;
    unsigned long long offset;
    std::string dev;
    unsigned long inode;
    std::string pathname;

    ProcMap() : pid(0), startAddress(0), endAddress(0), length(0), protection(0),
                readable(false), writeable(false), executable(false),
                is_private(false), is_shared(false),
                is_ro(false), is_rw(false), is_rx(false),
                offset(0), inode(0) {}

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
    inline std::string toString()
    {
        return KittyUtils::String::Fmt("%llx-%llx %c%c%c%c %llx %s %lu %s",
            startAddress, endAddress,
            readable ? 'r' : '-', writeable ? 'w' : '-', executable ? 'x' : '-', is_private ? 'p' : 's',
            offset, dev.c_str(), inode, pathname.c_str());
    }
  };

  /*
   * reads /proc/[pid]/cmdline
   */
  std::string getProcessName(pid_t pid);

  /*
   * find process ID by matching /proc/[pid]/cmdline
   */
  pid_t getProcessID(const std::string &processName);

  /*
   * Gets integer variable from /proc/[pid]/status
   */
  int getStatusInteger(pid_t pid, const std::string &var);

  /*
   * Gets info of all maps in /proc/[pid]/maps
   */
  std::vector<ProcMap> getAllMaps(pid_t pid);

  /*
   * Gets info of all maps which pathname equals name in provided maps vector
   */
  std::vector<ProcMap> getMapsEqual(const std::vector<ProcMap>& maps, const std::string& name);
  /*
   * Gets info of all maps which pathname equals name in /proc/[pid]/maps
   */
  std::vector<ProcMap> getMapsEqual(pid_t pid, const std::string &name);

  /*
   * Gets info of all maps which pathname contains name in provided maps vector
   */
  std::vector<ProcMap> getMapsContain(const std::vector<ProcMap>& maps, const std::string& name);
  /*
   * Gets info of all maps which pathname contains name in /proc/[pid]/maps
   */
  std::vector<ProcMap> getMapsContain(pid_t pid, const std::string &name);

  /*
   * Gets info of all maps which pathname ends with name in provided maps vector
   */
  std::vector<ProcMap> getMapsEndWith(const std::vector<ProcMap>& maps, const std::string& name);
  /*
   * Gets info of all maps which pathname ends with name in /proc/[pid]/maps
   */
  std::vector<ProcMap> getMapsEndWith(pid_t pid, const std::string &name);

  /*
   * Gets map info of an address in provided maps vector
   */
  ProcMap getAddressMap(const std::vector<ProcMap>& maps, uintptr_t address);
  /*
   * Gets map info of an address in /proc/[pid]/maps
   */
  ProcMap getAddressMap(pid_t pid, uintptr_t address);

  #ifdef __ANDROID__
    std::string getAppDirectory(const std::string &pkg);
  #endif
}
