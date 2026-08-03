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

bool KittyMemoryMgr::dumpMemRange(uintptr_t start, uintptr_t end, const std::string &destination) const
{
    if (!isMemValid())
        return false;

    if (start >= end)
    {
        KITTY_LOGE("dumpMemRange: Invalid range %p-%p.", (void *)start, (void *)end);
        return false;
    }

    KittyMemIO memIO;
    if (!memIO.init(_pid))
    {
        KITTY_LOGE("dumpMemRange: Failed to access process memory (%s).", strerror(memIO.lastErrno()));
        return false;
    }

    KittyIOFile destIO(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (!destIO.open())
    {
        KITTY_LOGE("dumpMemRange: failed opening destination (%s).", destIO.lastStrError().c_str());
        return false;
    }

    std::vector<char> buffer(KT_IO_CHUNK_SIZE);
    uintptr_t current = start;

    while (current < end)
    {
        size_t chunkSize = std::min<size_t>(KT_IO_CHUNK_SIZE, end - current);

        /*
         * Keep inaccessible memory as zero bytes.
         * This preserves the original virtual offsets.
         */
        memset(buffer.data(), 0, chunkSize);

        memIO.Read(current, buffer.data(), chunkSize, MemMode::SkipInaccessiblePages);

        /*
         * Always write the full chunk.
         */
        size_t written = destIO.write(buffer.data(), chunkSize);

        if (written != chunkSize)
        {
            KITTY_LOGE("dumpMemRange: Write failed at %p (%zu/%zu).", (void *)current, written, chunkSize);
            destIO.close();
            return false;
        }

        current += chunkSize;
    }

    destIO.close();
    return true;
}

bool KittyMemoryMgr::dumpMemFileMappings(const std::string &memFile, const std::string &destination) const
{
    if (!isMemValid() || memFile.empty() || destination.empty())
        return false;

    auto fileMappings = KittyMemoryEx::getFileMappings(_pid, memFile);
    if (fileMappings.empty())
        return false;

    std::string outPath = destination;
    kt_stat64_t st{};

    if (kt_stat64(destination.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
    {
        // Destination is an existing directory.
        if (access(destination.c_str(), W_OK) != 0)
            return false;

        size_t pos = memFile.find_last_of("/\\");
        outPath += (outPath.back() == '/' || outPath.back() == '\\') ? "" : "/";
        outPath += (pos == std::string::npos) ? memFile : memFile.substr(pos + 1);
    }
    else
    {
        // Destination is a file path.
        if (kt_stat64(outPath.c_str(), &st) == 0)
        {
            // Existing file: must be writable.
            if (access(outPath.c_str(), W_OK) != 0)
                return false;
        }
        else
        {
            // New file: parent directory must be writable.
            size_t pos = outPath.find_last_of("/\\");
            std::string parent = (pos == std::string::npos) ? "." : outPath.substr(0, pos);

            if (access(parent.c_str(), W_OK) != 0)
                return false;
        }
    }

    bool dumpedAtLeastOne = false;

    for (size_t i = 0; i < fileMappings.size(); ++i)
    {
        const auto &mapping = fileMappings[i];

        std::string filePath = outPath;

        if (fileMappings.size() > 1)
        {
            size_t dot = filePath.find_last_of('.');
            if (dot != std::string::npos)
                filePath.insert(dot, "_" + std::to_string(i));
            else
                filePath += "_" + std::to_string(i);
        }

        if (dumpMemRange(mapping.front().startAddress, mapping.back().endAddress, filePath))
        {
            dumpedAtLeastOne = true;
        }
    }

    return dumpedAtLeastOne;
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
