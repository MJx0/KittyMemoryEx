#include "KittyMemoryEx.hpp"
#include "KittyIOFile.hpp"

namespace KittyMemoryEx
{
    std::string getProcessName(pid_t pid)
    {
        if (pid <= 0)
            return "";

        char filePath[256] = {0};
        snprintf(filePath, sizeof(filePath), "/proc/%d/cmdline", pid);

        errno = 0;
        FILE *fp = fopen(filePath, "r");
        if (!fp)
        {
            KITTY_LOGE("Couldn't open cmdline file %s, error=%s", filePath, strerror(errno));
            return "";
        }

        char cmdline[128] = {0};
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);
        return cmdline;
    }

    pid_t getProcessID(const std::string &processName)
    {
        if (processName.empty())
            return 0;

        pid_t pid = 0;

        errno = 0;
        DIR *dir = opendir("/proc/");
        if (!dir)
        {
            KITTY_LOGE("Couldn't open /proc/, error=%s", strerror(errno));
            return pid;
        }

        dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr)
        {
            int entry_pid = atoi(entry->d_name);
            if (entry_pid > 0)
            {
                if (processName == getProcessName(entry_pid))
                {
                    pid = entry_pid;
                    break;
                }
            }
        }
        closedir(dir);
        return pid;
    }

    int getStatusInteger(pid_t pid, const std::string &var)
    {
        if (pid <= 0)
            return 0;

        int retVal = -1;

        char filePath[256] = {0};
        snprintf(filePath, sizeof(filePath), "/proc/%d/status", pid);

        errno = 0;
        FILE *fp = fopen(filePath, "r");
        if (!fp)
        {
            KITTY_LOGE("Couldn't open status file %s, error=%s", filePath, strerror(errno));
            return retVal;
        }

        size_t var_len = var.length();
        char line[100] = {0};
        while (fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, var.c_str(), var_len) == 0 && line[var_len] == ':')
            {
                retVal = strtol(&line[var_len + 1], nullptr, 10);
                break;
            }
        }
        fclose(fp);
        return retVal;
    }

    std::vector<ProcMap> getAllMaps(pid_t pid)
    {
        std::vector<ProcMap> retMaps;
        if (pid <= 0)
            return retMaps;

        char filePath[256] = {0};
        snprintf(filePath, sizeof(filePath), "/proc/%d/maps", pid);

        errno = 0;
        FILE *fp = fopen(filePath, "r");
        if (!fp)
        {
            KITTY_LOGE("Couldn't open maps file %s, error=%s", filePath, strerror(errno));
            return retMaps;
        }

        char line[512] = {0};
        while (fgets(line, sizeof(line), fp))
        {
            ProcMap map;
            map.pid = pid;

            char perms[5] = {0}, dev[11] = {0}, pathname[256] = {0};
            // parse a line in maps file
            // (format) startAddress-endAddress perms offset dev inode pathname
            sscanf(line, "%llx-%llx %s %llx %s %lu %s", 
                   &map.startAddress, &map.endAddress,
                   perms, &map.offset, dev, &map.inode, pathname);

            map.length = map.endAddress - map.startAddress;
            map.dev = dev;
            map.pathname = pathname;

            if (perms[0] == 'r')
            {
                map.protection |= PROT_READ;
                map.readable = true;
            }
            if (perms[1] == 'w')
            {
                map.protection |= PROT_WRITE;
                map.writeable = true;
            }
            if (perms[2] == 'x')
            {
                map.protection |= PROT_EXEC;
                map.executable = true;
            }

            map.is_private = (perms[3] == 'p');
            map.is_shared = (perms[3] == 's');

            map.is_rx = (strncmp(perms, "r-x", 3) == 0);
            map.is_rw = (strncmp(perms, "rw-", 3) == 0);
            map.is_ro = (strncmp(perms, "r--", 3) == 0);

            retMaps.push_back(map);
        }

        fclose(fp);

        if (retMaps.empty())
        {
            KITTY_LOGE("getAllMaps err couldn't find any map");
        }
        return retMaps;
    }

    std::vector<ProcMap> getMapsEqual(const std::vector<ProcMap>& maps, const std::string& name)
    {
        std::vector<ProcMap> retMaps;

        if (maps.empty() || name.empty())
            return retMaps;

        for (auto &it : maps)
            if (it.isValid() && !it.isUnknown() && it.pathname == name)
                retMaps.push_back(it);

        return retMaps;
    }

    std::vector<ProcMap> getMapsEqual(pid_t pid, const std::string& name)
    {
        return getMapsEqual(getAllMaps(pid), name);
    }

    std::vector<ProcMap> getMapsContain(const std::vector<ProcMap>& maps, const std::string& name)
    {
        std::vector<ProcMap> retMaps;

        if (maps.empty() || name.empty())
            return retMaps;

        for (auto &it : maps)
            if (it.isValid() && !it.isUnknown() && KittyUtils::String::Contains(it.pathname, name))
                retMaps.push_back(it);

        return retMaps;
    }

    std::vector<ProcMap> getMapsContain(pid_t pid, const std::string& name)
    {
        return getMapsContain(getAllMaps(pid), name);
    }

    std::vector<ProcMap> getMapsEndWith(const std::vector<ProcMap>& maps, const std::string& name)
    {
        std::vector<ProcMap> retMaps;

        if (maps.empty() || name.empty())
            return retMaps;

        for (auto &it : maps)
            if (it.isValid() && !it.isUnknown() && KittyUtils::String::EndsWith(it.pathname, name))
                retMaps.push_back(it);

        return retMaps;
    }

    std::vector<ProcMap> getMapsEndWith(pid_t pid, const std::string& name)
    {
        return getMapsEndWith(getAllMaps(pid), name);
    }

    ProcMap getAddressMap(const std::vector<ProcMap>& maps, uintptr_t address)
    {
        if (maps.empty() || !address)
            return {};

        for (auto &it : maps)
            if (it.isValid() && it.contains(address))
                return it;

        return {};
    }

    ProcMap getAddressMap(pid_t pid, uintptr_t address)
    {
        return getAddressMap(getAllMaps(pid), address);
    }

#ifdef __ANDROID__
    std::string getAppDirectory(const std::string &pkg)
    {
        std::string directory = "/data/app/", base_apk = "base.apk", ret;
        KittyIOFile::listFilesCallback(directory, [&](const std::string& filePath)
        {
            if (KittyUtils::fileNameFromPath(filePath) == base_apk)
            {
                const std::string fileDir = KittyUtils::fileDirectory(filePath);
                if (strstr(fileDir.c_str(), pkg.c_str()))
                {
                    ret = fileDir;
                    return true;
                }
            }
            return false;
        });
        return ret;
    }
#endif

} // KittyMemoryEx