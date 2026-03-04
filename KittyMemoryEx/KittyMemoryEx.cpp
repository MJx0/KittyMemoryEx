#include "KittyMemoryEx.hpp"
#include "KittyIOFile.hpp"
#include <fstream>


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
            KITTY_LOGD("Couldn't open cmdline file %s, error=%s", filePath,
                       strerror(errno));
            return "";
        }

        char cmdline[128] = {0};
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);
        return cmdline;
    }

    std::vector<pid_t> getProcessIDs(const std::string &processName)
    {
        std::vector<pid_t> pids;

        if (processName.empty())
            return pids;

        errno = 0;
        DIR *dir = opendir("/proc/");
        if (!dir)
        {
            KITTY_LOGD("Couldn't open /proc/, error=%s", strerror(errno));
            return pids;
        }

        dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr)
        {
            int entry_pid = atoi(entry->d_name);
            if (entry_pid > 0)
            {
                if (processName == getProcessName(entry_pid))
                {
                    pids.push_back(entry_pid);
                }
            }
        }
        closedir(dir);
        return pids;
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
            KITTY_LOGD("Couldn't open /proc/, error=%s", strerror(errno));
            return pid;
        }

        dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr)
        {
            if (entry->d_name[0] == '.')
                continue;

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

    std::vector<pid_t> getAllThreads(pid_t pid)
    {
        std::vector<pid_t> tids;
        if (pid <= 0)
            return tids;

        char filePath[256] = {0};
        snprintf(filePath, sizeof(filePath), "/proc/%d/task", pid);

        errno = 0;
        DIR *dir = opendir(filePath);
        if (!dir)
        {
            KITTY_LOGD("Couldn't open %s, error=%s", filePath, strerror(errno));
            return tids;
        }

        dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr)
        {
            if (entry->d_name[0] == '.')
                continue;

            int entry_tid = atoi(entry->d_name);
            if (entry_tid > 0)
            {
                tids.push_back(entry_tid);
            }
        }
        closedir(dir);
        return tids;
    }

    bool ProcStatus::parse(const std::string &path, ProcStatus *out)
    {        
        if (out)
            out->data.clear();

        std::ifstream file(path.c_str());
        if (!file.is_open())
            return false;

        std::string line;

        while (std::getline(file, line))
        {
            std::size_t colon = line.find(':');
            if (colon == std::string::npos)
                continue;

            std::string key = line.substr(0, colon);

            while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back())))
                key.pop_back();

            const char *p = line.c_str() + colon + 1;

            while (*p && std::isspace(static_cast<unsigned char>(*p)))
                ++p;

            std::string value(p);

            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
                value.pop_back();

            if (out)
                out->data.emplace(std::move(key), std::string(p));
        }

        return true;
    }

    bool ProcStatus::getIntFast(const std::string &path, const std::string &var, int *out)
    {
        if (out)
            *out = 0;

        errno = 0;
        FILE *fp = fopen(path.c_str(), "r");
        if (!fp)
        {
            KITTY_LOGD("Couldn't open status file %s, error=%s", path.c_str(), strerror(errno));
            return false;
        }

        size_t var_len = var.length();
        char line[100] = {0};
        bool found = false;
        while (fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, var.c_str(), var_len) == 0 && line[var_len] == ':')
            {
                if (out)
                    *out = strtol(&line[var_len + 1], nullptr, 10);
                found = true;
                break;
            }
        }
        fclose(fp);
        return found;
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
            KITTY_LOGD("Couldn't open maps file %s, error=%s", filePath, strerror(errno));
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
            sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %s %lu %s",
                   &map.startAddress, &map.endAddress, perms, &map.offset, dev,
                   &map.inode, pathname);

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
            KITTY_LOGD("getAllMaps err couldn't find any map");
        }
        return retMaps;
    }

    std::vector<ProcMap> getMaps(pid_t pid, EProcMapFilter filter,
                                 const std::string &name,
                                 const std::vector<ProcMap> &maps)
    {
        std::vector<ProcMap> retMaps;

        for (auto &it : (maps.empty() ? getAllMaps(pid) : maps))
        {
            if (it.isValid())
            {
                switch (filter)
                {
                case EProcMapFilter::Equal:
                    if (it.pathname == name)
                        retMaps.push_back(it);
                    break;
                case EProcMapFilter::StartWith:
                    if (KittyUtils::String::StartsWith(it.pathname, name))
                        retMaps.push_back(it);
                    break;
                case EProcMapFilter::EndWith:
                    if (KittyUtils::String::EndsWith(it.pathname, name))
                        retMaps.push_back(it);
                    break;
                case EProcMapFilter::Contains:
                default:
                    if (KittyUtils::String::Contains(it.pathname, name))
                        retMaps.push_back(it);
                    break;
                }
            }
        }

        return retMaps;
    }

    ProcMap getAddressMap(pid_t pid, uintptr_t address, const std::vector<ProcMap> &maps)
    {
        if (!address)
            return {};

        address = KittyUtils::untagHeepPtr(address);

        for (auto &it : (maps.empty() ? getAllMaps(pid) : maps))
            if (it.isValid() && it.contains(address))
                return it;

        return {};
    }

#ifdef __ANDROID__
    std::string getAppDirectory(const std::string &pkg)
    {
        std::string directory = "/data/app/", base_apk = "base.apk", ret;
        KittyIOFile::listFilesCallback(directory, [&](const std::string &filePath) {
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

} // namespace KittyMemoryEx