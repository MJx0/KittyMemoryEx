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
            KITTY_LOGD("Couldn't open cmdline file %s, error=%s", filePath, strerror(errno));
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
            sscanf(line,
                   "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %s %lu %s",
                   &map.startAddress,
                   &map.endAddress,
                   perms,
                   &map.offset,
                   dev,
                   &map.inode,
                   pathname);

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

    std::vector<ProcMap> getMaps(pid_t pid,
                                 EProcMapFilter filter,
                                 const std::string &name,
                                 const std::vector<ProcMap> &maps)
    {
        std::vector<ProcMap> retMaps;
        regex_t re{};
        bool isRegex = (filter == EProcMapFilter::Regex);

        if (isRegex)
        {
            if (regcomp(&re, name.c_str(), REG_EXTENDED | REG_NOSUB) != 0)
                return retMaps;
        }

        for (auto &it : (maps.empty() ? getAllMaps(pid) : maps))
        {
            if (!it.isValid())
                continue;

            bool match = false;
            switch (filter)
            {
            case EProcMapFilter::Equal:
                match = (it.pathname == name);
                break;
            case EProcMapFilter::StartWith:
                match = KittyUtils::String::startsWith(it.pathname, name);
                break;
            case EProcMapFilter::EndWith:
                match = KittyUtils::String::endsWith(it.pathname, name);
                break;
            case EProcMapFilter::Regex:
                match = (regexec(&re, it.pathname.c_str(), 0, NULL, 0) == 0);
                break;
            case EProcMapFilter::Contains:
            default:
                match = KittyUtils::String::contains(it.pathname, name);
                break;
            }

            if (match)
            {
                retMaps.push_back(it);
            }
        }

        if (isRegex)
            regfree(&re);

        return retMaps;
    }

    std::vector<ProcMap> getMaps(EProcMapFilter filter, const std::string &name, const std::vector<ProcMap> &maps)
    {
        std::vector<ProcMap> retMaps;
        regex_t re{};
        bool isRegex = (filter == EProcMapFilter::Regex);

        if (isRegex)
        {
            if (regcomp(&re, name.c_str(), REG_EXTENDED | REG_NOSUB) != 0)
                return retMaps;
        }

        for (const auto &it : maps)
        {
            if (!it.isValid())
                continue;

            bool match = false;
            switch (filter)
            {
            case EProcMapFilter::Equal:
                match = (it.pathname == name);
                break;
            case EProcMapFilter::StartWith:
                match = KittyUtils::String::startsWith(it.pathname, name);
                break;
            case EProcMapFilter::EndWith:
                match = KittyUtils::String::endsWith(it.pathname, name);
                break;
            case EProcMapFilter::Regex:
                match = (regexec(&re, it.pathname.c_str(), 0, NULL, 0) == 0);
                break;
            case EProcMapFilter::Contains:
            default:
                match = KittyUtils::String::contains(it.pathname, name);
                break;
            }

            if (match)
            {
                retMaps.push_back(it);
            }
        }

        if (isRegex)
            regfree(&re);

        return retMaps;
    }

    ProcMap getAddressMap(pid_t pid, uintptr_t address, const std::vector<ProcMap> &maps)
    {
        if (!address)
            return {};

        address = KittyUtils::untagHeepPtr(address);

        if (!maps.empty())
        {
            auto it = std::lower_bound(maps.begin(), maps.end(), address, [](const ProcMap &m, uintptr_t val) {
                return m.endAddress <= val;
            });

            if (it != maps.end() && address >= it->startAddress && address < it->endAddress)
            {
                return *it;
            }
        }
        else
        {
            auto pmaps = getAllMaps(pid);
            auto it = std::lower_bound(pmaps.begin(), pmaps.end(), address, [](const ProcMap &m, uintptr_t val) {
                return m.endAddress <= val;
            });

            if (it != pmaps.end() && address >= it->startAddress && address < it->endAddress)
            {
                return *it;
            }
        }

        return {};
    }

#ifdef __ANDROID__
    std::string getAppDirectory(const std::string &pkg)
    {
        std::string directory = "/data/app/", base_apk = "base.apk", ret;
        KittyIOFile::listFilesCallback(directory, [&](const std::string &filePath) {
            if (KittyUtils::Path::fileName(filePath) == base_apk)
            {
                const std::string fileDir = KittyUtils::Path::fileDirectory(filePath);
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