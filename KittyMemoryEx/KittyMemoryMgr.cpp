#include "KittyMemoryMgr.hpp"
#include "KittyMemoryEx.hpp"

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

#ifdef __LP64__
    linkerScanner = LinkerScannerMgr(_pMemOp.get(),
                                     elfScanner.findElf("/linker64", EScanElfType::Native, EScanElfFilter::System));
#else
    linkerScanner = LinkerScannerMgr(_pMemOp.get(),
                                     elfScanner.findElf("/linker", EScanElfType::Native, EScanElfFilter::System));
#endif

    nbScanner = NativeBridgeScannerMgr(_pMemOp.get(), &memScanner, &elfScanner);

#endif

    if (trace.pid() != pid)
    {
        trace = KittyTraceMgr(pid);
    }

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

bool KittyMemoryMgr::dumpMemRange(uintptr_t start, uintptr_t end, const std::string &destination) const
{
    if (!isMemValid())
        return false;

    if (start >= end)
    {
        KITTY_LOGE("dumpMemRange: start(%p) is equal or greater than end(%p).", (void *)start, (void *)end);
        return false;
    }

    bool ok = false;
    std::vector<char> memBuffer(end - start, 0);
    if (_eMemOp == EK_MEM_OP_IO)
    {
        ok = _pMemOp->Read(start, memBuffer.data(), memBuffer.size()) > 0x1000;
    }
    else
    {
        KittyMemIO memIO = {};
        if (memIO.init(_pid))
        {
            ok = memIO.Read(start, memBuffer.data(), memBuffer.size()) > 0x1000;
        }
    }

    if (ok)
    {
        KittyIOFile destIO(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (destIO.open())
        {
            ok = destIO.write(memBuffer.data(), memBuffer.size()) > 0x1000;
            destIO.close();
            return ok;
        }
    }

    return false;
}

bool KittyMemoryMgr::dumpMemFile(const std::string &memFile, const std::string &destination) const
{
    if (!isMemValid() || memFile.empty() || destination.empty())
        return false;

    auto fileMaps = KittyMemoryEx::getMaps(_pid, EProcMapFilter::EndWith, memFile);
    if (fileMaps.empty())
        return false;

    auto firstMap = fileMaps.front();
    uintptr_t lastEnd = firstMap.endAddress;

    for (size_t i = 1; i < fileMaps.size(); ++i)
    {
        const auto &it = fileMaps[i];
        if (firstMap.inode != 0 && it.inode == firstMap.inode && it.startAddress == lastEnd)
        {
            lastEnd = it.endAddress;
            continue;
        }
        break;
    }

    return dumpMemRange(firstMap.startAddress, lastEnd, destination);
}

bool KittyMemoryMgr::dumpMemELF(const ElfScanner &elf, const std::string &destination) const
{
    if (!isMemValid() || !elf.base() || !elf.loadSize())
        return false;

    bool dumped = dumpMemRange(elf.base(), elf.end(), destination);
    if (dumped && elf.isFixedBySoInfo())
    {
        KittyIOFile destIO(destination, O_WRONLY);
        destIO.open();
        KT_ElfW(Ehdr) fixedHdr = elf.header();
        destIO.pwrite(0, &fixedHdr, sizeof(fixedHdr));
        destIO.close();
    }

    return dumped;
}
