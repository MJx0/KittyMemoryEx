#include "KittyMemoryMgr.hpp"

bool KittyMemoryMgr::initialize(pid_t pid, EKittyMemOP eMemOp, bool initMemPatch)
{
    _init = false;
    _pid = pid;

    if (_pid <= 0)
    {
        KITTY_LOGE("KittyMemoryMgr: Invalid arg (pid).");
        return false;
    }

    _process_name = KittyMemoryEx::getProcessName(_pid);

    if (_pMemOp.get())
        _pMemOp.reset();

    _eMemOp = eMemOp;
    switch (eMemOp)
    {
    case EK_MEM_OP_SYSCALL:
        _pMemOp = std::make_unique<KittyMemSys>();
        break;
    case EK_MEM_OP_IO:
        _pMemOp = std::make_unique<KittyMemIO>();
        break;
    default:
        KITTY_LOGE("KittyMemoryMgr: Unknown memory operation.");
        return false;
    }

    if (!_pMemOp->init(_pid))
    {
        KITTY_LOGE("KittyMemoryMgr: Couldn't initialize memory operation.");
        return false;
    }

    _init = true;

    // patching mem only avaialabe for IO operation
    if (initMemPatch)
    {
        if (eMemOp == EK_MEM_OP_IO)
        {
            memPatch = MemoryPatchMgr(_pMemOp.get());
            memBackup = MemoryBackupMgr(_pMemOp.get());
        }
        else
        {
            if (_pMemOpPatch.get())
                _pMemOpPatch.reset();

            _pMemOpPatch = std::make_unique<KittyMemIO>();
            if (_pMemOpPatch->init(pid))
            {
                memPatch = MemoryPatchMgr(_pMemOpPatch.get());
                memBackup = MemoryBackupMgr(_pMemOpPatch.get());
            }
            else
            {
                KITTY_LOGW("KittyMemoryMgr: Couldn't initialize IO memory operation for memory patching.");
            }
        }
    }

    memScanner = KittyScannerMgr(_pMemOp.get());
    elfScanner = ElfScannerMgr(_pMemOp.get());

#ifdef __ANDROID__
    // refs https://fadeevab.com/shared-library-injection-on-android-8/
    uintptr_t defaultCaller = getElfBaseMap("libRS.so").startAddress;
#else
    uintptr_t defaultCaller = 0;
#endif
    trace = KittyTraceMgr(_pMemOp.get(), defaultCaller);

    return true;
}

size_t KittyMemoryMgr::readMem(uintptr_t address, void *buffer, size_t len) const
{
    if (!isMemValid() || !buffer || !len)
        return 0;

    return _pMemOp->Read(address, buffer, len);
}

size_t KittyMemoryMgr::writeMem(uintptr_t address, void *buffer, size_t len) const
{
    if (!isMemValid() || !buffer || !len)
        return 0;

    return _pMemOp->Write(address, buffer, len);
}

std::string KittyMemoryMgr::readMemStr(uintptr_t address, size_t maxLen) const
{
    if (!isMemValid() || !address || !maxLen)
        return "";

    return _pMemOp->ReadStr(address, maxLen);
}

bool KittyMemoryMgr::writeMemStr(uintptr_t address, std::string str) const
{
    if (!isMemValid() || !address || str.empty())
        return false;

    return _pMemOp->WriteStr(address, str);
}

bool KittyMemoryMgr::isValidELF(uintptr_t elfBase) const
{
    if (!isMemValid() || !elfBase)
        return false;

    char magic[4] = {0};
    return readMem(elfBase, magic, sizeof(magic)) && memcmp(magic, "\177ELF", 4) == 0;
}

KittyMemoryEx::ProcMap KittyMemoryMgr::getElfBaseMap(const std::string &elfName) const
{
    KittyMemoryEx::ProcMap ret{};

    if (!isMemValid() || elfName.empty())
        return ret;

    auto maps = KittyMemoryEx::getMapsContain(_pid, elfName);
    for (auto &it : maps)
    {
        if (isValidELF(it.startAddress) && elfScanner.createWithMap(it).isValid())
        {
            ret = it;
            break;
        }
    }

    return ret;
}

bool KittyMemoryMgr::dumpMemRange(uintptr_t start, uintptr_t end, const std::string &destination) const
{
    if (!isMemValid())
        return false;

    if (start >= end)
    {
        KITTY_LOGE("dumpMemRange: start(%p) is equal or greater than end(%p).", (void *)start, (void *)end);
        return false;
    }

    char memPath[256] = {0};
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", _pid);
    KittyIOFile srcFile(memPath, O_RDONLY);
    if (!srcFile.Open())
    {
        KITTY_LOGE("dumpMemRange: Couldn't open mem file %s, error=%s", memPath, srcFile.lastStrError().c_str());
        return false;
    }

    KittyIOFile dstFile(destination, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    dstFile.Delete();
    if (!dstFile.Open())
    {
        KITTY_LOGE("dumpMemRange: Couldn't open destination file %s, error=%s", destination.c_str(), dstFile.lastStrError().c_str());
        return false;
    }

    size_t displaySize = (end - start);
    static const char *units[] = {"B", "KB", "MB", "GB"};
    int u;
    for (u = 0; displaySize > 1024; u++)
        displaySize /= 1024;

    size_t dumpSize = (end - start);
    void *dmmap = mmap(nullptr, dumpSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!dmmap)
    {
        KITTY_LOGE("dumpMemRange: failed to allocate memory for dump with size %zu%s.", dumpSize, units[u]);
        return false;
    }

    KITTY_LOGI("dumpMemRange: Dumping: [ %p - %p | Size: %zu%s ] ...", (void *)start, (void *)end, displaySize, units[u]);

    size_t read_sz = srcFile.Read(start, dmmap, dumpSize);
    if (!read_sz)
    {
        KITTY_LOGE("dumpMemRange: failed to read memory range (%p - %p).", (void *)start, (void *)end);
        munmap(dmmap, dumpSize);
        return false;
    }

    if (read_sz != dumpSize)
        KITTY_LOGW("dumpMemRange: dump size %zu but bytes read %zu. error=%s.", dumpSize, read_sz, srcFile.lastStrError().c_str());

    ssize_t write_sz = dstFile.Write(0, dmmap, dumpSize);
    if (write_sz <= 0)
    {
        KITTY_LOGE("dumpMemRange: failed to write memory range (%p - %p).", (void *)start, (void *)end);
        munmap(dmmap, dumpSize);
        return false;
    }

    if ((size_t)write_sz != dumpSize)
        KITTY_LOGW("Dumping memory: dump size %zu but bytes written %zu. error=%s.", dumpSize, write_sz, dstFile.lastStrError().c_str());

    KITTY_LOGI("dumpMemRange: Dumped (%p - %p) at %s.", (void *)start, (void *)end, destination.c_str());

    munmap(dmmap, dumpSize);
    return true;
}

bool KittyMemoryMgr::dumpMemFile(const std::string &memFile, const std::string &destination) const
{
    if (!isMemValid() || memFile.empty() || destination.empty())
        return false;

    auto fileMaps = KittyMemoryEx::getMapsEndWith(_pid, memFile);
    if (fileMaps.empty())
        return false;

    auto firstMap = fileMaps.front();
    fileMaps.erase(fileMaps.begin());

    uintptr_t lastEnd = firstMap.endAddress;
    if (fileMaps.size() > 1)
    {
        for (auto &it : fileMaps)
        {
            if (firstMap.inode != it.inode || it.startAddress != lastEnd)
                break;

            lastEnd = it.endAddress;
        }
    }

    return dumpMemRange(firstMap.startAddress, lastEnd, destination);
}

bool KittyMemoryMgr::dumpMemELF(uintptr_t elfBase, const std::string &destination) const
{
    if (!isMemValid() || !elfBase)
        return false;

    ElfScanner elf = elfScanner.createWithBase(elfBase);
    return elf.isValid() && dumpMemRange(elfBase, elfBase + elf.loadSize(), destination);
}