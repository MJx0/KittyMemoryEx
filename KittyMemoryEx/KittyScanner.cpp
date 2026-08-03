#include "KittyScanner.hpp"
#include "KittyMemoryEx.hpp"

// refs
// https://github.com/learn-more/findpattern-bench

bool compare(const uint8_t *data, const uint8_t *pattern, const char *mask)
{
    for (; *mask; ++mask, ++data, ++pattern)
    {
        if (*mask == 'x' && *data != *pattern)
            return false;
    }
    return !*mask;
}

uintptr_t findInRange(uintptr_t start, uintptr_t end, const uint8_t *pattern, const std::string &mask)
{
    if (mask.empty() || start >= end || (end - start) < mask.length())
        return 0;

    const size_t mask_len = mask.length();
    const uint8_t *scan_start = reinterpret_cast<const uint8_t *>(start);
    const uint8_t *scan_end = reinterpret_cast<const uint8_t *>(end - mask_len);

    // Anchor memchr on the first required ('x') byte in the mask.
    size_t anchor_index = 0;
    while (anchor_index < mask_len && mask[anchor_index] != 'x')
        ++anchor_index;

    // All-wildcard mask matches immediately at the start of the range.
    if (anchor_index == mask_len)
        return start;

    const char *mask_data = mask.data();
    const uint8_t anchor_byte = pattern[anchor_index];
    const uint8_t *anchor_scan_start = scan_start + anchor_index;
    const uint8_t *anchor_scan_end = scan_end + anchor_index;

    const uint8_t *cur = anchor_scan_start;
    while (cur <= anchor_scan_end)
    {
        cur = static_cast<const uint8_t *>(memchr(cur, anchor_byte, (anchor_scan_end - cur) + 1));
        if (!cur)
            break;

        const uint8_t *candidate = cur - anchor_index;
        if (compare(candidate, pattern, mask_data))
            return reinterpret_cast<uintptr_t>(candidate);

        cur++;
    }

    return 0;
}

std::vector<uintptr_t> KittyScannerMgr::findBytesAll(uintptr_t start,
                                                     uintptr_t end,
                                                     const char *bytes,
                                                     const std::string &mask) const
{
    std::vector<uintptr_t> results;

    if (!_pMem || start >= end || !bytes || mask.empty() || (end - start) < mask.length())
        return results;

    const size_t kPageSize = KTGetPageSize();
    const size_t pattern_len = mask.length();
    const size_t total_size = end - start;

    results.reserve(128);

    std::vector<char> buf(std::min(total_size, KT_SCANNER_CHUNK_SIZE), 0);
    uintptr_t current_remote = start;

    while (current_remote < end)
    {
        const size_t bytes_left = end - current_remote;
        if (bytes_left < pattern_len)
            break;

        const size_t bytes_to_read = std::min(buf.size(), bytes_left);
        const size_t bytes_read = _pMem->Read(current_remote, buf.data(), bytes_to_read, MemMode::SkipInaccessiblePages);

        // Handle failed reads or partial page reads on unmapped/protected memory
        if (bytes_read < pattern_len)
        {
            const size_t page_offset = current_remote % kPageSize;
            const size_t bytes_to_next_page = kPageSize - page_offset;

            // Skip to the next page boundary or past read bytes (whichever advances further)
            current_remote += std::max(bytes_read, bytes_to_next_page);
            continue;
        }

        const uintptr_t local_base = reinterpret_cast<uintptr_t>(buf.data());
        const uintptr_t local_end = local_base + bytes_read;
        uintptr_t current_local = local_base;

        while (current_local < local_end)
        {
            uintptr_t found_local = findInRange(current_local,
                                                local_end,
                                                reinterpret_cast<const uint8_t *>(bytes),
                                                mask);
            if (!found_local)
                break;

            const size_t offset = found_local - local_base;
            results.push_back(current_remote + offset);

            current_local = found_local + 1;
        }

        // Slide the window forward based on actual bytes read to handle chunk boundaries
        current_remote += (bytes_read - pattern_len + 1);
    }

    return results;
}

uintptr_t KittyScannerMgr::findBytesFirst(uintptr_t start,
                                          uintptr_t end,
                                          const char *bytes,
                                          const std::string &mask) const
{
    if (!_pMem || start >= end || !bytes || mask.empty() || (end - start) < mask.length())
        return 0;

    const size_t kPageSize = KTGetPageSize();
    const size_t pattern_len = mask.length();
    const size_t total_size = end - start;

    std::vector<char> buf(std::min(total_size, KT_SCANNER_CHUNK_SIZE), 0);
    uintptr_t current_remote = start;

    while (current_remote < end)
    {
        const size_t bytes_left = end - current_remote;
        if (bytes_left < pattern_len)
            break;

        const size_t bytes_to_read = std::min(buf.size(), bytes_left);
        const size_t bytes_read = _pMem->Read(current_remote, buf.data(), bytes_to_read, MemMode::SkipInaccessiblePages);

        // Handle failed reads or partial page reads on unmapped/protected memory
        if (bytes_read < pattern_len)
        {
            const size_t page_offset = current_remote % kPageSize;
            const size_t bytes_to_next_page = kPageSize - page_offset;

            // Skip to the next page boundary or past read bytes (whichever advances further)
            current_remote += std::max(bytes_read, bytes_to_next_page);
            continue;
        }

        const uintptr_t local_base = reinterpret_cast<uintptr_t>(buf.data());
        const uintptr_t local_end = local_base + bytes_read;

        uintptr_t found_local = findInRange(local_base, local_end, reinterpret_cast<const uint8_t *>(bytes), mask);
        if (found_local)
        {
            const size_t offset = found_local - local_base;
            return current_remote + offset;
        }

        // Slide the window forward based on actual bytes read to handle chunk boundaries
        current_remote += (bytes_read - pattern_len + 1);
    }

    return 0;
}

std::vector<uintptr_t> KittyScannerMgr::findHexAll(uintptr_t start,
                                                   uintptr_t end,
                                                   std::string hex,
                                                   const std::string &mask) const
{
    std::vector<uintptr_t> results;

    if (!_pMem || start >= end || mask.empty() || (end - start) < mask.length() ||
        !KittyUtils::String::validateHex(hex))
        return results;

    const size_t scan_size = mask.length();
    if ((hex.length() / 2) != scan_size)
        return results;

    std::vector<char> pattern(scan_size, 0);
    KittyUtils::Data::fromHex(hex, &pattern[0]);

    results = findBytesAll(start, end, pattern.data(), mask);
    return results;
}

uintptr_t KittyScannerMgr::findHexFirst(uintptr_t start, uintptr_t end, std::string hex, const std::string &mask) const
{
    if (!_pMem || start >= end || mask.empty() || (end - start) < mask.length() ||
        !KittyUtils::String::validateHex(hex))
        return 0;

    const size_t scan_size = mask.length();
    if ((hex.length() / 2) != scan_size)
        return 0;

    std::vector<char> pattern(scan_size, 0);
    KittyUtils::Data::fromHex(hex, &pattern[0]);

    return findBytesFirst(start, end, pattern.data(), mask);
}

std::vector<uintptr_t> KittyScannerMgr::findIdaPatternAll(uintptr_t start,
                                                          uintptr_t end,
                                                          const std::string &pattern) const
{
    std::vector<uintptr_t> results;

    if (!_pMem || start >= end || pattern.empty())
        return results;

    std::vector<char> bytes;
    std::string mask;

    bytes.reserve(pattern.size() / 2);
    mask.reserve(pattern.size() / 2);

    auto hexValue = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9')
            return c - '0';

        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;

        return 0;
    };

    const size_t len = pattern.size();

    for (size_t i = 0; i < len;)
    {
        if (pattern[i] == ' ')
        {
            i++;
            continue;
        }

        if (pattern[i] == '?')
        {
            bytes.push_back(0);
            mask.push_back('?');
            i += (i + 1 < len && pattern[i + 1] == '?') ? 2 : 1;
            continue;
        }

        if (i + 1 < len && std::isxdigit(static_cast<unsigned char>(pattern[i])) &&
            std::isxdigit(static_cast<unsigned char>(pattern[i + 1])))
        {
            bytes.push_back(static_cast<char>((hexValue(pattern[i]) << 4) | hexValue(pattern[i + 1])));
            mask.push_back('x');
            i += 2;
            continue;
        }

        // invalid character
        i++;
    }

    if (bytes.empty() || bytes.size() != mask.size())
        return results;

    return findBytesAll(start, end, bytes.data(), mask);
}


uintptr_t KittyScannerMgr::findIdaPatternFirst(uintptr_t start, uintptr_t end, const std::string &pattern) const
{
    if (!_pMem || start >= end || pattern.empty())
        return 0;

    std::vector<char> bytes;
    std::string mask;

    bytes.reserve(pattern.size() / 2);
    mask.reserve(pattern.size() / 2);

    auto hexValue = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9')
            return c - '0';

        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;

        return 0;
    };

    const size_t len = pattern.size();

    for (size_t i = 0; i < len;)
    {
        if (pattern[i] == ' ')
        {
            i++;
            continue;
        }

        if (pattern[i] == '?')
        {
            bytes.push_back(0);
            mask.push_back('?');
            i += (i + 1 < len && pattern[i + 1] == '?') ? 2 : 1;
            continue;
        }

        if (i + 1 < len && std::isxdigit(static_cast<unsigned char>(pattern[i])) &&
            std::isxdigit(static_cast<unsigned char>(pattern[i + 1])))
        {
            bytes.push_back(static_cast<char>((hexValue(pattern[i]) << 4) | hexValue(pattern[i + 1])));
            mask.push_back('x');
            i += 2;
            continue;
        }

        i++;
    }

    if (bytes.empty() || bytes.size() != mask.size())
        return 0;

    return findBytesFirst(start, end, bytes.data(), mask);
}

std::vector<uintptr_t> KittyScannerMgr::findDataAll(uintptr_t start, uintptr_t end, const void *data, size_t size) const
{
    std::vector<uintptr_t> results;

    if (!_pMem || start >= end || !data || size < 1)
        return results;

    std::string mask(size, 'x');

    results = findBytesAll(start, end, reinterpret_cast<const char *>(data), mask);
    return results;
}

uintptr_t KittyScannerMgr::findDataFirst(uintptr_t start, uintptr_t end, const void *data, size_t size) const
{
    if (!_pMem || start >= end || !data || size < 1)
        return 0;

    std::string mask(size, 'x');

    return findBytesFirst(start, end, reinterpret_cast<const char *>(data), mask);
}

/* ======================= ElfScanner ======================= */

// refs https://gist.github.com/resilar/24bb92087aaec5649c9a2afc0b4350c8

ElfScanner::ElfScanner(IKittyMemOp *pMem, uintptr_t elfBase, const std::vector<KittyMemoryEx::ProcMap> &maps)
{
    _pMem = nullptr;
    _elfBase = 0;
    _ehdr = {};
    _phdr = 0;
    _loads = 0;
    _loadBias = 0;
    _loadSize = 0;
    _dynamic = 0;
    _stringTable = 0;
    _symbolTable = 0;
    _strsz = 0;
    _syment = sizeof(KT_ElfW(Sym));
    _fixedBySoInfo = false;
    _symbols_init = false;
    _dsymbols_init = false;

    if (!pMem || !elfBase)
        return;

    _pMem = pMem;
    _elfBase = elfBase;

    // verify address
    auto elfBaseMap = KittyMemoryEx::getAddressMap(_pMem->processID(), elfBase, maps);
    if (!elfBaseMap.isValid() || !elfBaseMap.readable || elfBase != elfBaseMap.startAddress)
    {
        KITTY_LOGD("ElfScanner: (%p) is not a valid ELF base address.", (void *)elfBase);
        return;
    }

    // read ELF header
    if (_pMem->Read(_elfBase, &_ehdr, sizeof(_ehdr)) != sizeof(_ehdr))
    {
        KITTY_LOGD("ElfScanner: Failed to read ELF (%p) header.", (void *)_elfBase);
        return;
    }

    // verify ELF header
    if (memcmp(_ehdr.e_ident, "\177ELF", 4) != 0)
    {
        KITTY_LOGD("ElfScanner: (%p) is not a valid ELF.", (void *)_elfBase);
        return;
    }

    // check ELF bit
    if (_ehdr.e_ident[EI_CLASS] != KT_ELF_EICLASS)
    {
        KITTY_LOGD("ElfScanner: ELF class mismatch (%p).", (void *)_elfBase);
        return;
    }

    if (_ehdr.e_ident[EI_DATA] != ELFDATA2LSB)
    {
        KITTY_LOGD("ElfScanner: (%p) data encoding is not little endian.", (void *)elfBase);
        return;
    }

    if (_ehdr.e_ident[EI_VERSION] != EV_CURRENT)
    {
        KITTY_LOGD("ElfScanner: (%p) ELF header version mismatch.", (void *)elfBase);
        return;
    }

    if (_ehdr.e_type != ET_EXEC && _ehdr.e_type != ET_DYN)
    {
        KITTY_LOGD("ElfScanner: (%p) is not a executable or dynamic "
                   "library.",
                   (void *)elfBase);
        return;
    }

    // check common header values
    if (!_ehdr.e_phoff || !_ehdr.e_phnum || !_ehdr.e_phentsize)
    {
        KITTY_LOGD("ElfScanner: Invalid header values (%p).", (void *)_elfBase);
        return;
    }

    if (!KittyMemoryEx::getAddressMap(_pMem->processID(), _elfBase + _ehdr.e_phoff, maps).readable)
    {
        KITTY_LOGD("ElfScanner: Invalid phdr (%p + %p) = %p.",
                   (void *)_elfBase,
                   (void *)_ehdr.e_phoff,
                   (void *)(_elfBase + _ehdr.e_phoff));
        return;
    }

    _phdr = _elfBase + _ehdr.e_phoff;

    // read all program headers
    std::vector<char> phdrs_buf(_ehdr.e_phnum * _ehdr.e_phentsize);
    if (!_pMem->Read(_phdr, &phdrs_buf[0], phdrs_buf.size()))
    {
        KITTY_LOGD("ElfScanner: Failed to read ELF (%p) program headers.", (void *)_elfBase);
        return;
    }

    // find load bias
    uintptr_t min_vaddr = UINTPTR_MAX, max_vaddr = 0;
    uintptr_t load_vaddr = 0, load_memsz = 0, load_filesz = 0;
    for (KT_ElfW(Half) i = 0; i < _ehdr.e_phnum; i++)
    {
        KT_ElfW(Phdr) phdr_entry = {};
        memcpy(&phdr_entry, phdrs_buf.data() + (i * _ehdr.e_phentsize), _ehdr.e_phentsize);
        _phdrs.push_back(phdr_entry);

        if (phdr_entry.p_type == PT_LOAD)
        {
            _loads++;

            load_vaddr = phdr_entry.p_vaddr;
            load_memsz = phdr_entry.p_memsz;
            load_filesz = phdr_entry.p_filesz;

            if (phdr_entry.p_vaddr < min_vaddr)
                min_vaddr = phdr_entry.p_vaddr;

            if (phdr_entry.p_vaddr + phdr_entry.p_memsz > max_vaddr)
                max_vaddr = phdr_entry.p_vaddr + phdr_entry.p_memsz;
        }
    }

    if (!_loads)
    {
        KITTY_LOGD("ElfScanner: No loads entry for ELF (%p).", (void *)_elfBase);
        return;
    }

    if (!max_vaddr)
    {
        KITTY_LOGD("ElfScanner: Failed to find load size for ELF (%p).", (void *)_elfBase);
        return;
    }

    min_vaddr = KT_PAGE_START(min_vaddr);
    max_vaddr = KT_PAGE_END(max_vaddr);

    _loadBias = _elfBase - min_vaddr;
    _loadSize = max_vaddr - min_vaddr;

    uintptr_t seg_start = load_vaddr + _loadBias;
    uintptr_t seg_mem_end = KT_PAGE_END((seg_start + load_memsz));
    uintptr_t seg_file_end = KT_PAGE_END((seg_start + load_filesz));
    uintptr_t bss_start = 0, bss_end = 0;
    if (seg_mem_end > seg_file_end)
    {
        bss_start = seg_file_end;
        bss_end = seg_mem_end;
    }

    for (const auto &it : maps)
    {
        if (it.startAddress >= _elfBase && it.endAddress <= (_elfBase + _loadSize))
        {
            if (it.startAddress == _elfBase)
            {
                _baseSegment = it;
            }

            _segments.push_back(it);

            if (it.readable && !it.executable &&
                (it.pathname == "[anon:.bss]" || (elfBaseMap.inode != 0 && it.inode == 0) ||
                 (it.startAddress >= bss_start && it.endAddress <= bss_end)))
            {
                _bssSegments.push_back(it);
            }
        }

        if (it.endAddress >= (_elfBase + _loadSize))
            break;
    }

    // read all dynamics
    for (auto &phdr : _phdrs)
    {
        if (phdr.p_type == PT_DYNAMIC)
        {
            if (phdr.p_vaddr == 0 || phdr.p_memsz == 0)
                break;
            if (!KittyMemoryEx::getAddressMap(_pMem->processID(), _loadBias + phdr.p_vaddr, maps).readable)
                break;
            if (!KittyMemoryEx::getAddressMap(_pMem->processID(), _loadBias + phdr.p_vaddr + (phdr.p_memsz - 1), maps)
                     .readable)
                break;

            _dynamic = _loadBias + phdr.p_vaddr;

            std::vector<KT_ElfW(Dyn)> dyn_buff(phdr.p_memsz / sizeof(KT_ElfW(Dyn)));
            if (!_pMem->Read(_dynamic, &dyn_buff[0], phdr.p_memsz))
            {
                KITTY_LOGD("ElfScanner: Failed to read dynamic for ELF (%p).", (void *)_elfBase);
                break;
            }

            for (auto &dyn : dyn_buff)
            {
                if (dyn.d_tag == DT_NULL)
                    break;

                // set required dynamics for symbol lookup
                switch (dyn.d_tag)
                {
                    // mandatory
                case DT_STRTAB: // string table
                    _stringTable = dyn.d_un.d_ptr;
                    break;
                    // mandatory
                case DT_SYMTAB: // symbol table
                    _symbolTable = dyn.d_un.d_ptr;
                    break;
                    // mandatory
                case DT_STRSZ: // string table size
                    _strsz = dyn.d_un.d_val;
                    break;
                    // mandatory
                case DT_SYMENT: // symbol entry size
                    _syment = dyn.d_un.d_val;
                    break;
                default:
                    break;
                }

                _dynamics.push_back(dyn);
            }

            break;
        }
    }

    auto fix_table_address = [&](uintptr_t &table_addr) {
        if (table_addr && table_addr < _loadBias)
            table_addr += _loadBias;

        if (!KittyMemoryEx::getAddressMap(_pMem->processID(), table_addr, maps).readable)
            table_addr = 0;
    };

    fix_table_address(_stringTable);
    fix_table_address(_symbolTable);

    _filepath = elfBaseMap.pathname;
    _realpath = elfBaseMap.pathname;
    if (!elfBaseMap.pathname.empty() && elfBaseMap.offset != 0)
    {
        KittyUtils::Zip::ZipEntryInfo ent{};
        if (KittyUtils::Zip::findEntryInfoByDataOffset(elfBaseMap.pathname, elfBaseMap.offset, &ent) &&
            !ent.fileName.empty())
        {
            _realpath += '!';
            _realpath += ent.fileName;
        }
    }
}

#ifdef __ANDROID__
ElfScanner::ElfScanner(IKittyMemOp *pMem, const kitty_soinfo_t &soinfo, const std::vector<KittyMemoryEx::ProcMap> &maps)
{
    _pMem = nullptr;
    _elfBase = 0;
    _ehdr = {};
    _phdr = 0;
    _loads = 0;
    _loadBias = 0;
    _loadSize = 0;
    _dynamic = 0;
    _stringTable = 0;
    _symbolTable = 0;
    _strsz = 0;
    _syment = 0;
    _fixedBySoInfo = false;
    _symbols_init = false;
    _dsymbols_init = false;

    if (!pMem)
        return;

    _pMem = pMem;
    _elfBase = soinfo.base;
    _phdr = soinfo.phdr;
    _loadBias = soinfo.bias;
    _loadSize = soinfo.size;
    _dynamic = soinfo.dyn;
    _stringTable = soinfo.strtab;
    _symbolTable = soinfo.symtab;
    _strsz = soinfo.strsz;
    _syment = sizeof(KT_ElfW(Sym));
    _filepath = soinfo.path;
    _realpath = soinfo.realpath;

    bool isLinker = KittyUtils::String::endsWith(soinfo.path, "/linker") ||
                    KittyUtils::String::endsWith(soinfo.path, "/linker64");
    if (!isLinker && (_elfBase == 0 || _loadSize == 0 || _loadBias == 0 || _phdr == 0 || _dynamic == 0 ||
                      _stringTable == 0 || _symbolTable == 0))
    {
        KITTY_LOGD("ElfScanner: Invalid soinfo!");
        KITTY_LOGD(
            "ElfScanner: elfBase: %p | bias: %p | phdr: %p | dyn: %p | strtab=%p | symtab=%p | strsz=%p | syment=%p",
            (void *)_elfBase,
            (void *)_loadBias,
            (void *)_phdr,
            (void *)_dynamic,
            (void *)_stringTable,
            (void *)_symbolTable,
            (void *)_strsz,
            (void *)_syment);
        *this = ElfScanner();
        return;
    }

    // fix for linker
    if (_elfBase == 0)
        _elfBase = KittyMemoryEx::getAddressMap(_pMem->processID(), soinfo.bias, maps).startAddress;
    if (_elfBase == 0)
        _elfBase = KittyMemoryEx::getAddressMap(_pMem->processID(), soinfo.phdr, maps).startAddress;
    if (_elfBase == 0)
        _elfBase = KittyMemoryEx::getAddressMap(_pMem->processID(), soinfo.dyn, maps).startAddress;
    if (_elfBase == 0)
        _elfBase = KittyMemoryEx::getAddressMap(_pMem->processID(), soinfo.symtab, maps).startAddress;
    if (_elfBase == 0)
        _elfBase = KittyMemoryEx::getAddressMap(_pMem->processID(), soinfo.strtab, maps).startAddress;

    // verify address
    auto elfBaseMap = KittyMemoryEx::getAddressMap(_pMem->processID(), _elfBase, maps);
    if (!elfBaseMap.isValid() || !elfBaseMap.readable || _elfBase != elfBaseMap.startAddress)
    {
        KITTY_LOGD("ElfScanner: Invalid base(%p) for soinfo(%p)", (void *)_elfBase, (void *)soinfo.ptr);
        *this = ElfScanner();
        return;
    }

    // read ELF header
    if (_pMem->Read(_elfBase, &_ehdr, sizeof(_ehdr)) != sizeof(_ehdr))
    {
        KITTY_LOGD("ElfScanner: Failed to read ELF header for soinfo(%p).", (void *)_elfBase);
        return;
    }

    // check if header is corrupted
    // some games like farlight have corrupted header and needs to be fixed by soinfo
    if (!isLinker && (memcmp(_ehdr.e_ident, "\177ELF", 4) != 0 || _ehdr.e_ident[EI_CLASS] != KT_ELF_EICLASS ||
                      _ehdr.e_ident[EI_DATA] != ELFDATA2LSB || _ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
                      (_ehdr.e_type != ET_EXEC && _ehdr.e_type != ET_DYN) || _ehdr.e_ehsize != sizeof(KT_ElfW(Ehdr)) ||
                      _ehdr.e_phentsize != sizeof(KT_ElfW(Phdr)) || _ehdr.e_phnum != soinfo.phnum ||
                      _ehdr.e_phoff != (soinfo.phdr - soinfo.base)))
    {
        KITTY_LOGD("ElfScanner: soinfo(%p) has corrupted header, fixing by soinfo...", (void *)soinfo.ptr);

        _ehdr.e_ident[EI_MAG0] = 0x7F;
        _ehdr.e_ident[EI_MAG1] = 'E';
        _ehdr.e_ident[EI_MAG2] = 'L';
        _ehdr.e_ident[EI_MAG3] = 'F';
        _ehdr.e_ident[EI_CLASS] = KT_ELF_EICLASS;
        _ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
        _ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        _ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
        _ehdr.e_ident[EI_ABIVERSION] = 0;

        _ehdr.e_type = ET_DYN;
        _ehdr.e_machine = soinfo.e_machine;
        _ehdr.e_version = EV_CURRENT;
        _ehdr.e_entry = 0;
        _ehdr.e_phoff = soinfo.phdr ? (soinfo.phdr - soinfo.base) : 0;
        _ehdr.e_phnum = soinfo.phnum;
        _ehdr.e_ehsize = sizeof(KT_ElfW(Ehdr));
        _ehdr.e_phentsize = sizeof(KT_ElfW(Phdr));
        _ehdr.e_shoff = 0;
        _ehdr.e_shentsize = sizeof(KT_ElfW(Shdr));
        _ehdr.e_shnum = 0;
        _ehdr.e_shstrndx = 0;
        _ehdr.e_flags = 0;

        _fixedBySoInfo = true;
    }

    // fix for linker
    if (_phdr == 0)
        _phdr = _elfBase + _ehdr.e_phoff;

    auto phdrMap = KittyMemoryEx::getAddressMap(_pMem->processID(), _phdr, maps);
    if (!phdrMap.readable || phdrMap.startAddress < _elfBase ||
        (_loadSize && phdrMap.endAddress > (_elfBase + _loadSize)))
    {
        KITTY_LOGD("ElfScanner: Invalid phdr(%p) for soinfo(%p).", (void *)_phdr, (void *)soinfo.ptr);
        *this = ElfScanner();
        return;
    }

    if (!isLinker)
    {
        auto dynMap = KittyMemoryEx::getAddressMap(_pMem->processID(), _dynamic, maps);
        if (!(dynMap.readable && dynMap.startAddress >= _elfBase && dynMap.endAddress <= (_elfBase + _loadSize)))
        {
            KITTY_LOGD("ElfScanner: Invalid dyn(%p) for soinfo(%p).", (void *)_dynamic, (void *)soinfo.ptr);
            *this = ElfScanner();
            return;
        }
    }

    // fix for ldplayer
    auto biasMap = KittyMemoryEx::getAddressMap(_pMem->processID(), _loadBias, maps);
    if (!(biasMap.readable && biasMap.startAddress >= _elfBase && biasMap.endAddress <= (_elfBase + _loadSize)))
    {
        KITTY_LOGD("ElfScanner: Invalid bias(%p) for soinfo(%p).", (void *)_loadBias, (void *)soinfo.ptr);
        _loadBias = 0;
    }

    // read all program headers
    std::vector<char> phdrs_buf(_ehdr.e_phnum * _ehdr.e_phentsize);
    if (!_pMem->Read(_phdr, &phdrs_buf[0], phdrs_buf.size()))
    {
        KITTY_LOGE("ElfScanner: Failed to read ELF (%p) program headers.", (void *)_elfBase);
        return;
    }

    uintptr_t min_vaddr = UINTPTR_MAX, max_vaddr = 0;
    uintptr_t load_vaddr = 0, load_memsz = 0, load_filesz = 0;
    for (KT_ElfW(Half) i = 0; i < _ehdr.e_phnum; i++)
    {
        KT_ElfW(Phdr) phdr_entry = {};
        memcpy(&phdr_entry, phdrs_buf.data() + (i * _ehdr.e_phentsize), _ehdr.e_phentsize);
        _phdrs.push_back(phdr_entry);

        if (phdr_entry.p_type == PT_LOAD)
        {
            _loads++;

            load_vaddr = phdr_entry.p_vaddr;
            load_memsz = phdr_entry.p_memsz;
            load_filesz = phdr_entry.p_filesz;

            if (phdr_entry.p_vaddr < min_vaddr)
                min_vaddr = phdr_entry.p_vaddr;

            if (phdr_entry.p_vaddr + phdr_entry.p_memsz > max_vaddr)
                max_vaddr = phdr_entry.p_vaddr + phdr_entry.p_memsz;
        }
    }

    if (!_loads)
    {
        KITTY_LOGE("ElfScanner: No loads entry for ELF (%p).", (void *)_elfBase);
        *this = ElfScanner();
        return;
    }

    if (!max_vaddr)
    {
        KITTY_LOGE("ElfScanner: Failed to find load size for ELF (%p).", (void *)_elfBase);
        *this = ElfScanner();
        return;
    }

    min_vaddr = KT_PAGE_START(min_vaddr);
    max_vaddr = KT_PAGE_END(max_vaddr);

    // fix for linker
    {
        if (_loadBias == 0)
            _loadBias = _elfBase - min_vaddr;

        if (_loadSize == 0)
            _loadSize = max_vaddr - min_vaddr;
    }

    uintptr_t seg_start = load_vaddr + _loadBias;
    uintptr_t seg_mem_end = KT_PAGE_END((seg_start + load_memsz));
    uintptr_t seg_file_end = KT_PAGE_END((seg_start + load_filesz));
    uintptr_t bss_start = 0, bss_end = 0;
    if (seg_mem_end > seg_file_end)
    {
        bss_start = seg_file_end;
        bss_end = seg_mem_end;
    }

    for (const auto &it : maps)
    {
        if (it.startAddress >= _elfBase && it.endAddress <= (_elfBase + _loadSize))
        {
            if (it.startAddress == _elfBase)
            {
                _baseSegment = it;
            }

            _segments.push_back(it);

            if (it.readable && !it.executable &&
                (it.pathname == "[anon:.bss]" || (elfBaseMap.inode != 0 && it.inode == 0) ||
                 (it.startAddress >= bss_start && it.endAddress <= bss_end)))
            {
                _bssSegments.push_back(it);
            }
        }

        if (it.endAddress >= (_elfBase + _loadSize))
            break;
    }

    // read all dynamics
    for (auto &phdr : _phdrs)
    {
        if (phdr.p_type == PT_DYNAMIC)
        {
            // fix for linker
            if (_dynamic == 0 && phdr.p_vaddr)
                _dynamic = _loadBias + phdr.p_vaddr;

            if (_dynamic == 0 || phdr.p_memsz == 0)
                break;
            if (!KittyMemoryEx::getAddressMap(_pMem->processID(), _dynamic, maps).readable)
                break;
            if (!KittyMemoryEx::getAddressMap(_pMem->processID(), _dynamic + (phdr.p_memsz - 1), maps).readable)
                break;

            std::vector<KT_ElfW(Dyn)> dyn_buff(phdr.p_memsz / sizeof(KT_ElfW(Dyn)));
            if (!_pMem->Read(_dynamic, &dyn_buff[0], phdr.p_memsz))
            {
                KITTY_LOGD("ElfScanner: Failed to read dynamic for ELF (%p).", (void *)_elfBase);
                break;
            }

            for (auto &dyn : dyn_buff)
            {
                if (dyn.d_tag == DT_NULL)
                    break;

                switch (dyn.d_tag)
                {
                case DT_STRTAB:
                    if (_stringTable == 0)
                        _stringTable = dyn.d_un.d_ptr;
                    break;
                case DT_SYMTAB:
                    if (_symbolTable == 0)
                        _symbolTable = dyn.d_un.d_ptr;
                    break;
                case DT_STRSZ:
                    if (_strsz == 0)
                        _strsz = dyn.d_un.d_val;
                    break;
                case DT_SYMENT:
                    _syment = dyn.d_un.d_val;
                    break;
                default:
                    break;
                }

                _dynamics.push_back(dyn);
            }

            break;
        }
    }

    auto fix_table_address = [&](uintptr_t &table_addr) {
        if (table_addr && table_addr < _loadBias)
            table_addr += _loadBias;

        if (!KittyMemoryEx::getAddressMap(_pMem->processID(), table_addr, maps).readable)
            table_addr = 0;
    };

    fix_table_address(_symbolTable);
    fix_table_address(_stringTable);
}
#endif

std::unordered_map<std::string, uintptr_t> ElfScanner::symbols()
{
    if (!_symbols_init && _loadBias && _stringTable && _symbolTable && _strsz && _syment)
    {
        _symbols_init = true;

        auto get_sym_address = [&](const KT_ElfW(Sym) * sym_ent) -> uintptr_t {
            return sym_ent->st_value < _loadBias ? _loadBias + sym_ent->st_value : sym_ent->st_value;
        };

        size_t symtab_sz = ((_stringTable > _symbolTable) ? (_stringTable - _symbolTable)
                                                          : (_symbolTable - _stringTable));
        std::vector<char> symtab_buff(symtab_sz, 0);
        std::vector<char> strtab_buff(_strsz, 0);

        if (_pMem->Read(_symbolTable, symtab_buff.data(), symtab_buff.size()) &&
            _pMem->Read(_stringTable, strtab_buff.data(), strtab_buff.size()))
        {
            uintptr_t sym_start = uintptr_t(symtab_buff.data());
            uintptr_t sym_end = uintptr_t(symtab_buff.data() + symtab_buff.size());
            uintptr_t sym_str_end = uintptr_t(strtab_buff.data() + strtab_buff.size());
            for (auto sym_entry = sym_start; (sym_entry + _syment) < sym_end; sym_entry += _syment)
            {
                const KT_ElfW(Sym) *curr_sym = reinterpret_cast<KT_ElfW(Sym) *>(sym_entry);

                if (curr_sym->st_name >= _strsz)
                    break;

                if (intptr_t(curr_sym->st_name) <= 0 || intptr_t(curr_sym->st_value) <= 0 ||
                    intptr_t(curr_sym->st_size) <= 0)
                    continue;

                if (KT_ELF_ST_TYPE(curr_sym->st_info) != STT_OBJECT && KT_ELF_ST_TYPE(curr_sym->st_info) != STT_FUNC)
                    continue;

                uintptr_t sym_str_addr = uintptr_t(strtab_buff.data() + curr_sym->st_name);
                if (!sym_str_addr || sym_str_addr >= sym_str_end)
                    continue;

                std::string sym_str = std::string(reinterpret_cast<const char *>(sym_str_addr));
                if (!sym_str.empty() && sym_str.data())
                    _symbolsMap[sym_str] = get_sym_address(curr_sym);
            }
        }
    }

    return _symbolsMap;
}

std::unordered_map<std::string, uintptr_t> ElfScanner::dsymbols()
{
    if (!_dsymbols_init && _loadBias && !_filepath.empty())
    {
        _dsymbols_init = true;

        auto get_sym_address = [&](const KT_ElfW(Sym) * sym_ent) -> uintptr_t {
            return sym_ent->st_value < _loadBias ? _loadBias + sym_ent->st_value : sym_ent->st_value;
        };

        KittyUtils::Zip::ZipEntryMMap mmap_info = {};
        if (isZipped())
        {
            if (!KittyUtils::Zip::mmapEntryByDataOffset(_filepath, _baseSegment.offset, &mmap_info))
                return _dsymbolsMap;
        }
        else
        {
            KittyIOFile elfFile(_filepath, O_RDONLY);
            if (!elfFile.open())
            {
                KITTY_LOGD("Failed to open file <%s> err(%s)", _filepath.c_str(), elfFile.lastStrError().c_str());
                return _dsymbolsMap;
            }
            size_t elfSize = elfFile.info().st_size;
            if (elfSize <= 0)
            {
                elfFile.close();
                KITTY_LOGD("stat failed for <%s>", _filepath.c_str());
                return _dsymbolsMap;
            }
            mmap_info.mappingBase = mmap(nullptr, elfSize, PROT_READ, MAP_PRIVATE, elfFile.fd(), 0);
            mmap_info.mappingSize = elfSize;
            mmap_info.data = reinterpret_cast<uint8_t *>(mmap_info.mappingBase);
            mmap_info.size = mmap_info.mappingSize;
            elfFile.close();
        }

        if (mmap_info.size == 0 || !mmap_info.data || mmap_info.data == ((void *)-1))
        {
            KITTY_LOGD("Failed to mmap <%s>", realPath().c_str());
            return _dsymbolsMap;
        }

        auto cleanup = [&] { munmap(mmap_info.mappingBase, mmap_info.mappingSize); };

        KT_ElfW(Ehdr) *ehdr = reinterpret_cast<KT_ElfW(Ehdr) *>(mmap_info.data);

        if (memcmp(ehdr->e_ident, "\177ELF", 4) != 0)
        {
            KITTY_LOGD("<%s> is not a valid ELF", realPath().c_str());
            cleanup();
            return _dsymbolsMap;
        }

        if (ehdr->e_phoff == 0 || ehdr->e_phentsize == 0 || ehdr->e_phnum == 0 ||
            ehdr->e_phoff + ehdr->e_phnum * sizeof(KT_ElfW(Phdr)) > mmap_info.size)
        {
            KITTY_LOGD("Invalid program header table in <%s>", filePath().c_str());
            cleanup();
            return _dsymbolsMap;
        }

        if (ehdr->e_shoff == 0 || ehdr->e_shentsize == 0 || ehdr->e_shnum == 0 ||
            ehdr->e_shoff + ehdr->e_shnum * sizeof(KT_ElfW(Shdr)) > mmap_info.size)
        {
            KITTY_LOGD("Invalid section header table in <%s>", filePath().c_str());
            cleanup();
            return _dsymbolsMap;
        }

        if (ehdr->e_shstrndx >= ehdr->e_shnum)
        {
            KITTY_LOGD("Invalid section header string table index in <%s>", filePath().c_str());
            cleanup();
            return _dsymbolsMap;
        }

        const KT_ElfW(Shdr) *shdr = reinterpret_cast<KT_ElfW(Shdr) *>(reinterpret_cast<char *>(mmap_info.data) +
                                                                      ehdr->e_shoff);
        const KT_ElfW(Shdr) *shstrtab_shdr = shdr + ehdr->e_shstrndx;

        if (shstrtab_shdr->sh_offset > mmap_info.size ||
            mmap_info.size - shstrtab_shdr->sh_offset < shstrtab_shdr->sh_size)
        {
            KITTY_LOGD("Invalid section header string table in <%s>", filePath().c_str());
            cleanup();
            return _dsymbolsMap;
        }

        const char *sectionstr = reinterpret_cast<char *>(reinterpret_cast<char *>(mmap_info.data) +
                                                          shstrtab_shdr->sh_offset);
        for (uint16_t i = 0; i < ehdr->e_shnum; ++i)
        {
            if (shdr[i].sh_type != SHT_SYMTAB)
                continue;

            if (shdr[i].sh_name >= shstrtab_shdr->sh_size)
                continue;

            std::string section_name = std::string(reinterpret_cast<const char *>(sectionstr + shdr[i].sh_name));
            if (section_name.compare(".symtab") != 0)
                continue;

            if (shdr[i].sh_entsize == 0 || (shdr[i].sh_offset + shdr[i].sh_size) > mmap_info.size ||
                shdr[i].sh_link >= ehdr->e_shnum ||
                (shdr[shdr[i].sh_link].sh_offset + shdr[shdr[i].sh_link].sh_size) > mmap_info.size)
                continue;

            const KT_ElfW(Sym) *symtab = reinterpret_cast<KT_ElfW(Sym) *>(reinterpret_cast<char *>(mmap_info.data) +
                                                                          shdr[i].sh_offset);
            const size_t symCount = shdr[i].sh_size / shdr[i].sh_entsize;
            const KT_ElfW(Shdr) *strtabShdr = &shdr[shdr[i].sh_link];
            const char *strtab = reinterpret_cast<char *>(reinterpret_cast<char *>(mmap_info.data) +
                                                          strtabShdr->sh_offset);

            for (size_t j = 0; j < symCount; ++j)
            {
                const KT_ElfW(Sym) *curr_sym = &symtab[j];
                if (!curr_sym || curr_sym->st_name >= strtabShdr->sh_size)
                    continue;

                if (intptr_t(curr_sym->st_value) <= 0 || intptr_t(curr_sym->st_size) <= 0)
                    continue;

                if (KT_ELF_ST_TYPE(curr_sym->st_info) != STT_OBJECT && KT_ELF_ST_TYPE(curr_sym->st_info) != STT_FUNC)
                    continue;

                std::string sym_str = std::string(reinterpret_cast<const char *>(strtab + curr_sym->st_name));
                if (!sym_str.empty() && sym_str.data())
                    _dsymbolsMap[sym_str] = get_sym_address(curr_sym);
            }
        }
        cleanup();
    }
    return _dsymbolsMap;
}

uintptr_t ElfScanner::findSymbol(const std::string &symbolName)
{
    const auto &syms = symbols();
    auto it = syms.find(symbolName);
    return it != syms.end() ? it->second : 0;
}

uintptr_t ElfScanner::findDebugSymbol(const std::string &symbolName)
{
    const auto &syms = dsymbols();
    auto it = syms.find(symbolName);
    return it != syms.end() ? it->second : 0;
}

bool ElfScannerMgr::isValidELF(uintptr_t elfBase) const
{
    if (!_pMem || !elfBase)
        return false;

    char magic[4] = {0};
    return _pMem->Read(elfBase, magic, sizeof(magic)) && memcmp(magic, "\177ELF", 4) == 0;
}

ElfScanner &ElfScannerMgr::getProgramElf()
{
    if (!_pMem)
        return _programElf;

    if (!_programElf.isValid() || !_programElf.dynamic())
    {
        std::string path = KittyUtils::String::fmt("/proc/%d/exe", _pMem->processID());
        char exePath[0xff] = {};
        int ret = int(readlink(path.c_str(), exePath, 0xff));
        if (ret == -1 || exePath[0] == '\0')
        {
            int err = errno;
            KITTY_LOGE("Failed to readlink \"%s\", error(%d): %s.", path.c_str(), err, strerror(err));
            return _programElf;
        }

        const auto allMaps = KittyMemoryEx::getAllMaps(_pMem->processID());
        std::vector<KittyMemoryEx::ProcMap> exeMaps;

#ifdef __ANDROID__
        // Fix for google emulator which has two app_process
        // Make sure to always get native one
        {
            std::string exeName = KittyUtils::Path::fileName(exePath);
            std::string binDir = KittyUtils::Path::fileDirectory(KittyUtils::Path::fileDirectory(exePath));
            exeMaps = KittyMemoryEx::getMaps(_pMem->processID(),
                                             KittyMemoryEx::EProcMapFilter::Equal,
                                             binDir + "/" + exeName,
                                             allMaps);
            if (exeMaps.empty())
            {
                exeMaps = KittyMemoryEx::getMaps(_pMem->processID(),
                                                 KittyMemoryEx::EProcMapFilter::Equal,
                                                 exePath,
                                                 allMaps);
            }
        }
#else
        exeMaps = KittyMemoryEx::getMaps(_pMem->processID(), KittyMemoryEx::EProcMapFilter::Equal, exePath, allMaps);
#endif

        for (const auto &it : exeMaps)
        {
            if (!it.readable || it.writeable)
                continue;

            _programElf = ElfScanner(_pMem, it.startAddress, allMaps);
            if (_programElf.isValid() && _programElf.dynamic())
                break;
        }
    }

    return _programElf;
}

#ifdef __ANDROID__
std::vector<ElfScanner> ElfScannerMgr::getAllELFs(EScanElfType type, EScanElfFilter filter)
#else
std::vector<ElfScanner> ElfScannerMgr::getAllELFs()
#endif
{
    std::vector<ElfScanner> elfs;

    if (!_pMem)
        return elfs;

#ifdef __ANDROID__
    const auto progMachine = getProgramElf().header().e_machine;
    static auto eMachineCheck = [](EScanElfType type, int a, int b) -> bool {
        return a == 0 || b == 0 || type == EScanElfType::Any || (type == EScanElfType::Native && a == b) ||
               (type == EScanElfType::Emulated && a != b);
    };

    const bool isAppFilter = filter == EScanElfFilter::App;
    const bool isSysFilter = filter == EScanElfFilter::System;
#endif

    auto maps = KittyMemoryEx::getAllMaps(_pMem->processID());
    if (maps.empty())
    {
        KITTY_LOGD("GetAllELFs: Failed to get process maps.");
        return elfs;
    }

    unsigned long lastElfNode = 0;

    for (auto &it : maps)
    {
#ifdef __LP64__
        if (it.startAddress >= (0x7fffffffffff - 0x1000))
            continue;
#else
        if (it.startAddress >= (0xffffffff - 0x1000))
            continue;
#endif

        if (!it.isValid() || !it.readable || it.writeable || it.is_shared || (it.inode != 0 && it.inode == lastElfNode))
            continue;

#ifdef __ANDROID__
        if (isAppFilter)
        {
            if (it.inode == 0 || (!KittyUtils::String::startsWith(it.pathname, "/data/") &&
                                  !KittyUtils::String::startsWith(it.pathname, "/proc/") &&
                                  !KittyUtils::String::startsWith(it.pathname, "/memfd:")))
                continue;
        }
        else if (isSysFilter)
        {
            if ((it.inode == 0 && it.pathname != "[vdso]") ||
                (!KittyUtils::String::startsWith(it.pathname, "/system/") &&
                 !KittyUtils::String::startsWith(it.pathname, "/apex/")))
                continue;
        }
#endif

        if (_cached_elfs.size() && _cached_elfs.count(it.startAddress) > 0)
        {
            auto elf = _cached_elfs[it.startAddress];
            if (elf.filePath() == it.pathname)
            {
#ifdef __ANDROID__
                if (eMachineCheck(type, progMachine, elf.header().e_machine))
#endif
                {
                    elfs.push_back(elf);
                }
                lastElfNode = elf.baseSegment().inode;
                continue;
            }
            else
            {
                _cached_elfs.erase(it.startAddress);
            }
        }

#ifdef __ANDROID__
        bool isFile = (!it.pathname.empty() && it.inode != 0);
        if (!isFile && it.pathname != "[vdso]" && !KittyUtils::String::startsWith(it.pathname, "/memfd:"))
            continue;

        if (it.pathname == "cfi shadow")
            continue;

        if (KittyUtils::String::startsWith(it.pathname, "/dev/") ||
            KittyUtils::String::startsWith(it.pathname, "/system/fonts/") ||
            KittyUtils::String::startsWith(it.pathname, "/data/priv-downloads/") ||
            KittyUtils::String::startsWith(it.pathname, "/data/misc/"))
            continue;

        if (KittyUtils::String::startsWith(it.pathname, "/system/etc/") &&
            !KittyUtils::String::endsWith(it.pathname, ".so"))
            continue;

        if (KittyUtils::String::startsWith(it.pathname, "/data/dalvik-cache/") ||
            KittyUtils::String::startsWith(it.pathname, "/system/") ||
            KittyUtils::String::startsWith(it.pathname, "/apex/com.android.") ||
            (KittyUtils::String::startsWith(it.pathname, "/data/app/") &&
             KittyUtils::String::contains(it.pathname, "/oat/")))
        {
            if (KittyUtils::String::endsWith(it.pathname, ".jar") ||
                KittyUtils::String::endsWith(it.pathname, ".art") ||
                KittyUtils::String::endsWith(it.pathname, ".oat") ||
                KittyUtils::String::endsWith(it.pathname, ".odex") || KittyUtils::String::endsWith(it.pathname, ".dex"))
                continue;
        }
#endif

        auto elf = ElfScanner(_pMem, it.startAddress, maps);
        if (elf.isValid())
        {
#ifdef __ANDROID__
            if (eMachineCheck(type, progMachine, elf.header().e_machine))
#endif
            {
                elfs.push_back(elf);
            }
            lastElfNode = elf.baseSegment().inode;
            _cached_elfs[it.startAddress] = elf;
        }
    }

    std::vector<uintptr_t> invalid_keys;
    for (auto &it : _cached_elfs)
    {
        if (it.first && !KittyMemoryEx::getAddressMap(_pMem->processID(), it.first, maps).readable)
        {
            invalid_keys.push_back(it.first);
        }
    }

    for (auto &it : invalid_keys)
    {
        _cached_elfs.erase(it);
    }

    return elfs;
}

#ifdef __ANDROID__
ElfScanner ElfScannerMgr::findElf(const std::string &path, EScanElfType type, EScanElfFilter filter)
#else
ElfScanner ElfScannerMgr::findElf(const std::string &path)
#endif
{
    ElfScanner ret{};

    if (!_pMem || path.empty())
        return ret;

    std::vector<ElfScanner> elfs;
    std::vector<ElfScanner> dyn_elfs;

#ifdef __ANDROID__
    const auto allElfs = getAllELFs(type, filter);
#else
    const auto allElfs = getAllELFs();
#endif
    for (const auto &it : allElfs)
    {
        if (it.isValid() && KittyUtils::String::endsWith(it.realPath(), path))
        {
            if (it.dynamic() && it.dynamics().size() > 0)
                dyn_elfs.push_back(it);
            else
                elfs.push_back(it);
        }
    }

    if (elfs.empty() && dyn_elfs.empty())
        return ret;

    if (dyn_elfs.size() > 0)
    {
        if (dyn_elfs.size() == 1)
            return dyn_elfs[0];

        int nMostSegments = 0;
        for (auto &it : dyn_elfs)
        {
            int numSegments = it.segments().size();
            // >= to get latest
            if (numSegments >= nMostSegments)
            {
                ret = it;
                nMostSegments = numSegments;
            }
        }
    }
    else if (elfs.size() > 0)
    {
        if (elfs.size() == 1)
            return elfs[0];

        int nMostSegments = 0;
        for (auto &it : elfs)
        {
            int numSegments = it.segments().size();
            // >= to get latest
            if (numSegments >= nMostSegments)
            {
                ret = it;
                nMostSegments = numSegments;
            }
        }
    }

    return ret;
}

#ifdef __ANDROID__
std::vector<std::pair<uintptr_t, ElfScanner>> ElfScannerMgr::findSymbolAll(const std::string &symbolName,
                                                                           EScanElfType type,
                                                                           EScanElfFilter filter)
#else
std::vector<std::pair<uintptr_t, ElfScanner>> ElfScannerMgr::findSymbolAll(const std::string &symbolName)
#endif
{
    std::vector<std::pair<uintptr_t, ElfScanner>> ret{};

#ifdef __ANDROID__
    auto elfs = getAllELFs(type, filter);
#else
    auto elfs = getAllELFs();
#endif
    for (auto &it : elfs)
    {
        uintptr_t sym = it.findSymbol(symbolName);
        if (sym != 0)
        {
            ret.emplace_back(sym, it);
        }
    }

    return ret;
}

uintptr_t ElfScannerMgr::findRemoteSymbol(const std::string &local_sym_name, uintptr_t local_sym_addr)
{
    if (!_pMem || local_sym_name.empty() || !local_sym_addr)
        return 0;

    ElfScanner r_lib{};
    KittyMemoryEx::ProcMap l_lib{};

    l_lib = KittyMemoryEx::getAddressMap(getpid(), local_sym_addr);
    if (l_lib.isValid())
        r_lib = findElf(l_lib.pathname);

    if (!r_lib.isValid())
    {
        KITTY_LOGD("KittyInjector: Failed to find %s, remote lib not found.", local_sym_name.c_str());
        return 0;
    }

    uintptr_t remote_address = r_lib.findSymbol(local_sym_name);

    // fallback
    if (!remote_address)
        remote_address = local_sym_addr - l_lib.startAddress + r_lib.base();

    return remote_address;
}

#ifdef __ANDROID__
LinkerScannerMgr::LinkerScannerMgr(IKittyMemOp *pMem, uintptr_t linkerBase) : ElfScanner(pMem, linkerBase)
{
    memset(&_linker_syms, 0, sizeof(_linker_syms));

    _init = false;

    if (!pMem || !isValid())
        return;

    _pMem = pMem;
    init();
}

LinkerScannerMgr::LinkerScannerMgr(IKittyMemOp *pMem, const ElfScanner &linkerElf) : ElfScanner(linkerElf)
{
    memset(&_linker_syms, 0, sizeof(_linker_syms));

    _init = false;

    if (!pMem || !isValid())
        return;

    _pMem = pMem;
    init();
}

bool LinkerScannerMgr::init()
{
    if (!_pMem || !isValid())
        return false;

    if (_init)
        return true;

    for (const auto &sym : dsymbols())
    {
        if (KittyUtils::String::startsWith(sym.first, "__dl__ZL11solist_head") ||
            KittyUtils::String::startsWith(sym.first, "__dl__ZL6solist"))
        {
            _linker_syms.solist = sym.second;
            continue;
        }
        if (KittyUtils::String::startsWith(sym.first, "__dl__ZL6somain"))
        {
            _linker_syms.somain = sym.second;
            continue;
        }
        if (KittyUtils::String::startsWith(sym.first, "__dl__ZL11solist_tail") ||
            KittyUtils::String::startsWith(sym.first, "__dl__ZL6sonext"))
        {
            _linker_syms.sonext = sym.second;
            continue;
        }
        if (_linker_syms.solist && _linker_syms.somain && _linker_syms.sonext)
            break;
    }

    if (!(_linker_syms.solist && _linker_syms.somain && _linker_syms.sonext))
    {
        return false;
    }

    KITTY_LOGD("solist(%zx) | somain(%zx) | sonext(%zx)", solist(), somain(), sonext());

    std::vector<char> solist_buf(KT_SOINFO_BUFFER_SZ, 0);
    _pMem->Read(solist(), solist_buf.data(), KT_SOINFO_BUFFER_SZ);

    std::vector<char> si_buf(KT_SOINFO_BUFFER_SZ, 0);
    uintptr_t somain_ptr = somain();
    _pMem->Read(somain_ptr ? somain_ptr : sonext(), si_buf.data(), KT_SOINFO_BUFFER_SZ);

    auto allMaps = KittyMemoryEx::getAllMaps(_pMem->processID());

    ElfScanner si_elf{};
    for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
    {
        uintptr_t possible_base = *(uintptr_t *)&si_buf[i];

        auto tmp_map = KittyMemoryEx::getAddressMap(_pMem->processID(), possible_base, allMaps);
        if (!tmp_map.isValid() || !tmp_map.readable || tmp_map.writeable || tmp_map.is_shared)
            continue;

        si_elf = ElfScanner(_pMem, possible_base, allMaps);
        if (si_elf.isValid())
        {
            _soinfo_offsets.base = i;
            break;
        }
    }

    static constexpr uintptr_t kNoOff = kitty_soinfo_offsets_t::noff;

    KITTY_LOGD("soinfo_base(%zx)", _soinfo_offsets.base);

    if (_soinfo_offsets.base == kNoOff)
        return false;

    for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
    {
        uintptr_t value = *(uintptr_t *)&si_buf[i];

        if (_soinfo_offsets.phdr == kNoOff && value == si_elf.phdr())
        {
            _soinfo_offsets.phdr = i;
            continue;
        }
        if (_soinfo_offsets.phnum == kNoOff && value == si_elf.header().e_phnum)
        {
            _soinfo_offsets.phnum = i;
            continue;
        }
        if (_soinfo_offsets.size == kNoOff &&
            (value == si_elf.loadSize() ||
             value ==
                 (si_elf.loadSize() + KittyMemoryEx::getAddressMap(_pMem->processID(), si_elf.end(), allMaps).length)))
        {
            _soinfo_offsets.size = i;
            continue;
        }
        if (_soinfo_offsets.dyn == kNoOff && value == si_elf.dynamic())
        {
            _soinfo_offsets.dyn = i;
            continue;
        }
        if (_soinfo_offsets.strtab == kNoOff && value == si_elf.stringTable())
        {
            _soinfo_offsets.strtab = i;
            continue;
        }
        if (_soinfo_offsets.symtab == kNoOff && value == si_elf.symbolTable())
        {
            _soinfo_offsets.symtab = i;
            continue;
        }
        if (_soinfo_offsets.bias == kNoOff && value == si_elf.loadBias() && i != _soinfo_offsets.base)
        {
            _soinfo_offsets.bias = i;
            continue;
        }
        if (_soinfo_offsets.strsz == kNoOff && value == si_elf.stringTableSize())
        {
            _soinfo_offsets.strsz = i;
            continue;
        }
    }

    KITTY_LOGD("soinfo_bias(%zx) | soinfo_size(%zx)", _soinfo_offsets.bias, _soinfo_offsets.size);
    KITTY_LOGD("soinfo_phdr(%zx, %zx) | soinfo_dyn(%zx)",
               _soinfo_offsets.phdr,
               _soinfo_offsets.phnum,
               _soinfo_offsets.dyn);
    KITTY_LOGD("soinfo_strtab(%zx, %zx) | soinfo_symtab(%zx)",
               _soinfo_offsets.strtab,
               _soinfo_offsets.strsz,
               _soinfo_offsets.symtab);

    if (_soinfo_offsets.size == kNoOff || _soinfo_offsets.bias == kNoOff || _soinfo_offsets.dyn == kNoOff ||
        _soinfo_offsets.symtab == kNoOff || _soinfo_offsets.strtab == kNoOff)
    {
        return false;
    }

    for (size_t i = 0; i < solist_buf.size(); i += sizeof(uintptr_t))
    {
        uintptr_t possible_next = *(uintptr_t *)&solist_buf[i];

        if (!KittyMemoryEx::getAddressMap(_pMem->processID(), possible_next + _soinfo_offsets.base, allMaps).readable)
            continue;

        uintptr_t possible_base = 0;
        _pMem->Read(possible_next + _soinfo_offsets.base, &possible_base, sizeof(uintptr_t));

        auto tmp_map = KittyMemoryEx::getAddressMap(_pMem->processID(), possible_base, allMaps);
        if (!tmp_map.isValid() || !tmp_map.readable || tmp_map.writeable || tmp_map.is_shared)
            continue;

        auto tmp_elf = ElfScanner(_pMem, possible_base, allMaps);
        if (tmp_elf.isValid())
        {
            if (!KittyMemoryEx::getAddressMap(_pMem->processID(), possible_next + _soinfo_offsets.size, allMaps)
                     .readable)
                continue;

            uintptr_t possible_size = 0;
            _pMem->Read(possible_next + _soinfo_offsets.size, &possible_size, sizeof(uintptr_t));
            if (possible_size == tmp_elf.loadSize() ||
                possible_size == (tmp_elf.loadSize() +
                                  KittyMemoryEx::getAddressMap(_pMem->processID(), tmp_elf.end(), allMaps).length))
            {
                _soinfo_offsets.next = i;
                break;
            }
        }
    }

    KITTY_LOGD("soinfo_sonext(%zx)", _soinfo_offsets.next);

    _init = _soinfo_offsets.next != kNoOff;
    return _init;
}

std::vector<kitty_soinfo_t> LinkerScannerMgr::allSoInfo() const
{
    std::vector<kitty_soinfo_t> infos{};

    if (!_pMem || !isValid() || !_init)
        return infos;

    auto maps = KittyMemoryEx::getAllMaps(_pMem->processID());
    uintptr_t si = solist(), prev = 0;
    while (si && KittyMemoryEx::getAddressMap(_pMem->processID(), si, maps).readable)
    {
        kitty_soinfo_t info = infoFromSoInfo_(si, maps);
        infos.push_back(info);

        prev = si;

        if (_pMem->Read(si + _soinfo_offsets.next, &si, sizeof(uintptr_t)) != sizeof(uintptr_t))
            break;

        if (si == prev)
            break;
    }
    return infos;
}

kitty_soinfo_t LinkerScannerMgr::findSoInfo(const std::string &name) const
{
    const auto list = allSoInfo();
    for (const auto &it : list)
    {
        if (KittyUtils::String::endsWith(it.realpath, name))
        {
            return it;
        }
    }
    return {};
}

kitty_soinfo_t LinkerScannerMgr::infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemoryEx::ProcMap> &maps) const
{
    kitty_soinfo_t info{};

    if (!_pMem || !isValid() || !_init)
        return info;

    std::vector<char> si_buf(KT_SOINFO_BUFFER_SZ, 0);
    if (!_pMem->Read(si, si_buf.data(), KT_SOINFO_BUFFER_SZ))
        return info;

    info.ptr = si;
    info.base = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.base);
    info.size = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.size);
    info.phdr = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.phdr);
    info.phnum = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.phnum);
    info.dyn = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.dyn);
    info.strtab = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.strtab);
    info.symtab = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.symtab);
    info.strsz = _soinfo_offsets.strsz != kitty_soinfo_offsets_t::noff
                     ? *(uintptr_t *)(si_buf.data() + _soinfo_offsets.strsz)
                     : 0;
    info.bias = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.bias);
    info.next = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.next);
    info.e_machine = header().e_machine;

    uintptr_t start_map_addr = info.base;
    if (start_map_addr == 0)
        start_map_addr = info.bias;
    if (start_map_addr == 0)
        start_map_addr = info.phdr;
    if (start_map_addr == 0)
        start_map_addr = info.dyn;
    if (start_map_addr == 0)
        start_map_addr = info.strtab;
    if (start_map_addr == 0)
        start_map_addr = info.symtab;

    auto si_map = KittyMemoryEx::getAddressMap(_pMem->processID(), start_map_addr, maps);
    if (si_map.isValid())
    {
        info.path = si_map.pathname;
        info.realpath = si_map.pathname;
        if (si_map.offset != 0)
        {
            KittyUtils::Zip::ZipEntryInfo ent{};
            if (KittyUtils::Zip::findEntryInfoByDataOffset(si_map.pathname, si_map.offset, &ent) &&
                !ent.fileName.empty())
            {
                info.realpath += '!';
                info.realpath += ent.fileName;
            }
        }
    }

    return info;
}

NativeBridgeScannerMgr::NativeBridgeScannerMgr(IKittyMemOp *pMem,
                                               KittyScannerMgr *memScanner,
                                               ElfScannerMgr *elfScanner)
{
    _pMem = pMem;
    _memScanner = memScanner;
    _elfScanner = elfScanner;

    _sohead = 0;

    _nbItf = 0;
    _nbItf_data_size = 0;
    _isHoudini = false;

    fnNativeBridgeInitialized = nullptr;

    memset(&_nbItf_data, 0, sizeof(_nbItf_data));

    _init = false;

    if (!_pMem || !_memScanner || !_elfScanner)
        return;

    init();
}

bool NativeBridgeScannerMgr::init()
{
    if (!_pMem || !_memScanner || !_elfScanner)
        return false;

    if (_init)
        return true;

    static constexpr uintptr_t kNoOff = kitty_soinfo_offsets_t::noff;

    _nbElf = _elfScanner->findElf("/libnativebridge.so", EScanElfType::Native, EScanElfFilter::System);
    if (!_nbElf.isValid())
    {
        KITTY_LOGD("NativeBridgeScanner: Failed to find libnativebrdge.so");
        return false;
    }

    *(uintptr_t *)&fnNativeBridgeInitialized = _nbElf.findSymbol("NativeBridgeInitialized");
    if (fnNativeBridgeInitialized == nullptr)
        *(uintptr_t *)&fnNativeBridgeInitialized = _nbElf.findSymbol("_ZN7android23NativeBridgeInitializedEv");

    _nbImplElf = _elfScanner->findElf("/libhoudini.so", EScanElfType::Native, EScanElfFilter::System);
    if (_nbImplElf.isValid())
        _isHoudini = true;
    else
        _nbImplElf = _elfScanner->findElf("/libndk_translation.so", EScanElfType::Native, EScanElfFilter::System);

    if (!_nbImplElf.isValid())
    {
        KITTY_LOGD("NativeBridgeScanner: Failed to find nativebridge implementation");
        return false;
    }

    _nbItf = _nbImplElf.findSymbol("NativeBridgeItf");
    if (_nbItf == 0)
    {
        KITTY_LOGD("NativeBridgeScanner: Failed to find export NativeBridgeItf");
        return false;
    }

    if (_pMem->Read(_nbItf, &_nbItf_data.version, sizeof(int)) != sizeof(int))
    {
        KITTY_LOGD("NativeBridgeScanner: Failed to read nativebridge version");
        return false;
    }

    _nbItf_data_size = nbItf_data_t::GetStructSize(_nbItf_data.version);
    if (_nbItf_data_size == 0)
    {
        KITTY_LOGD("NativeBridgeScanner: Unsupported nativebridge version (%d)", _nbItf_data.version);
        return false;
    }

    KITTY_LOGD("NativeBridgeScanner: Using nativebridge version (%d), data size (%p)",
               _nbItf_data.version,
               (void *)_nbItf_data_size);

    if (_pMem->Read(_nbItf, &_nbItf_data, _nbItf_data_size) != _nbItf_data_size)
    {
        KITTY_LOGD("NativeBridgeScanner: Failed to read NativeBridgeItf data");
        return false;
    }

    // replace for nb v2
    if (_nbItf_data.version < KT_NB_NAMESPACE_VERSION)
    {
        uintptr_t pLoadLibrary = _nbElf.findSymbol("NativeBridgeLoadLibrary");
        if (pLoadLibrary == 0)
            pLoadLibrary = _nbElf.findSymbol("_ZN7android23NativeBridgeLoadLibraryEPKci");

        uintptr_t pGetTrampoline = _nbElf.findSymbol("NativeBridgeGetTrampoline");
        if (pGetTrampoline == 0)
            pGetTrampoline = _nbElf.findSymbol("_ZN7android25NativeBridgeGetTrampolineEPvPKcS2_j");

        if (pLoadLibrary != 0)
            *(uintptr_t *)&_nbItf_data.loadLibrary = pLoadLibrary;

        if (pGetTrampoline != 0)
            *(uintptr_t *)&_nbItf_data.getTrampoline = pGetTrampoline;
    }

    // emulated linker for google emulators
#ifdef __LP64__
    LinkerScannerMgr emulinker = LinkerScannerMgr(_pMem,
                                                  _elfScanner->findElf("/linker64",
                                                                       EScanElfType::Emulated,
                                                                       EScanElfFilter::System));
#else
    LinkerScannerMgr emulinker = LinkerScannerMgr(_pMem,
                                                  _elfScanner->findElf("/linker",
                                                                       EScanElfType::Emulated,
                                                                       EScanElfFilter::System));
#endif

    if (!_isHoudini && emulinker.init())
    {
        _sohead = emulinker.solist();
        _soheadElf = *emulinker.asELF();
        _soinfo_offsets = emulinker.soinfo_offsets();

        KITTY_LOGD("NativeBridgeScanner: Using Emulated Linker for solist.");
    }
    else // Houdini
    {
        uintptr_t emudlAddress = 0;
        for (auto &it : _elfScanner->getAllELFs(EScanElfType::Emulated, EScanElfFilter::System))
        {
            if (KittyUtils::String::endsWith(it.realPath(), "/libdl.so"))
            {
                emudlAddress = it.base();
                break;
            }
        }

        if (emudlAddress == 0)
        {
            KITTY_LOGD("NativeBridgeScanner: Failed to find emulated libdl.so");
            return false;
        }

        auto emuElfs = _elfScanner->getAllELFs(EScanElfType::Emulated);
        if (emuElfs.empty())
        {
            KITTY_LOGD("NativeBridgeScanner: Failed to find any loaded emulated so");
            return false;
        }

        struct kt_so_data_t
        {
            uintptr_t soinfo = 0;
            int soinfo_next_count = 0;
            ElfScanner elf{};
            kitty_soinfo_offsets_t offsets{};
        };

        std::vector<kt_so_data_t> soheads;
        static const char *heads[] = {"/app_process", "/app_process64", "/libdl.so"};
        for (size_t i = 0; i < emuElfs.size(); i++)
        {
            if (emuElfs[i].base() < emudlAddress)
            {
                kt_so_data_t so{};
                soheads.push_back({0, 0, emuElfs[i], {}});
                continue;
            }

            for (auto &name : heads)
            {
                if (KittyUtils::String::endsWith(emuElfs[i].realPath(), name))
                {
                    kt_so_data_t so{};
                    soheads.push_back({0, 0, emuElfs[i], {}});
                }
            }
        }

        auto maps = KittyMemoryEx::getAllMaps(_pMem->processID());

        for (auto &sohead : soheads)
        {
            struct
            {
                uintptr_t phdr = 0;
                size_t phnum = 0;
            } data;

            data.phdr = sohead.elf.phdr();
            data.phnum = sohead.elf.header().e_phnum;

            KITTY_LOGD("NativeBridgeScanner: sohead phdr { %p, %zu }", (void *)(data.phdr), data.phnum);

            // search in bss first
            for (auto &it : _nbImplElf.segments())
            {
                if (it.is_rw)
                {
                    sohead.soinfo = _memScanner->findDataFirst(it.startAddress, it.endAddress, &data, sizeof(data));
                    if (sohead.soinfo)
                    {
                        KITTY_LOGD("NativeBridgeScanner: Found sohead->phdr ref (%p) at %s",
                                   (void *)sohead.soinfo,
                                   it.toString().c_str());
                        break;
                    }
                }
            }

            if (sohead.soinfo == 0)
            {
                // search in read-only "[anon:Mem_" or "[anon:linker_alloc]"
                for (auto &it : maps)
                {
                    if (!it.is_ro || it.executable || !it.is_private)
                        continue;

                    bool check1 = (KittyUtils::String::startsWith(it.pathname, "[anon:Mem_"));
                    bool check2 = (it.pathname == "[anon:linker_alloc]");
                    if (!check1 && !check2)
                        continue;

                    sohead.soinfo = _memScanner->findDataFirst(it.startAddress, it.endAddress, &data, sizeof(data));
                    if (sohead.soinfo)
                    {
                        KITTY_LOGD("NativeBridgeScanner: Found sohead->phdr ref (%p) at %s",
                                   (void *)sohead.soinfo,
                                   it.toString().c_str());
                        break;
                    }
                }
            }

            if (sohead.soinfo == 0)
            {
                // search in read-write "[anon:Mem_" or "[anon:linker_alloc]"
                for (auto &it : maps)
                {
                    if (!it.is_rw || it.executable || !it.is_private)
                        continue;

                    bool check1 = (KittyUtils::String::startsWith(it.pathname, "[anon:Mem_"));
                    bool check2 = (it.pathname == "[anon:linker_alloc]");
                    if (!check1 && !check2)
                        continue;

                    sohead.soinfo = _memScanner->findDataFirst(it.startAddress, it.endAddress, &data, sizeof(data));
                    if (sohead.soinfo)
                    {
                        KITTY_LOGD("NativeBridgeScanner: Found sohead->phdr ref (%p) at %s",
                                   (void *)sohead.soinfo,
                                   it.toString().c_str());
                        break;
                    }
                }
            }

            if (sohead.soinfo == 0)
                continue;

            std::vector<char> si_buf(KT_SOINFO_BUFFER_SZ, 0);
            _pMem->Read(sohead.soinfo, si_buf.data(), KT_SOINFO_BUFFER_SZ);

            for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
            {
                uintptr_t possible_next = *(uintptr_t *)&si_buf[i];
                if (!KittyMemoryEx::getAddressMap(_pMem->processID(), possible_next, maps).readable)
                    continue;

                std::vector<char> si_buf_inner(KT_SOINFO_BUFFER_SZ, 0);
                _pMem->Read(possible_next, si_buf_inner.data(), KT_SOINFO_BUFFER_SZ);

                ElfScanner si_elf{};
                for (size_t j = 0; j < si_buf_inner.size(); j += sizeof(uintptr_t))
                {
                    uintptr_t possible_base = *(uintptr_t *)&si_buf_inner[j];

                    auto tmp_map = KittyMemoryEx::getAddressMap(_pMem->processID(), possible_base, maps);
                    if (possible_base != tmp_map.startAddress || !tmp_map.isValid() || !tmp_map.readable ||
                        tmp_map.writeable || tmp_map.is_shared)
                        continue;

                    si_elf = ElfScanner(_pMem, possible_base, maps);
                    if (si_elf.isValid())
                    {
                        sohead.offsets.base = j;
                        break;
                    }
                }

                if (sohead.offsets.base == kNoOff)
                    continue;

                for (size_t j = 0; j < si_buf_inner.size(); j += sizeof(uintptr_t))
                {
                    uintptr_t value = *(uintptr_t *)&si_buf_inner[j];

                    if (sohead.offsets.phdr == kNoOff && value == si_elf.phdr())
                    {
                        sohead.offsets.phdr = j;
                        continue;
                    }
                    if (sohead.offsets.phnum == kNoOff && value == si_elf.header().e_phnum)
                    {
                        sohead.offsets.phnum = j;
                        continue;
                    }
                    if (sohead.offsets.size == kNoOff &&
                        (value == si_elf.loadSize() ||
                         value == (si_elf.loadSize() +
                                   KittyMemoryEx::getAddressMap(_pMem->processID(), si_elf.end(), maps).length)))
                    {
                        sohead.offsets.size = j;
                        continue;
                    }
                    if (sohead.offsets.dyn == kNoOff && value == si_elf.dynamic())
                    {
                        sohead.offsets.dyn = j;
                        continue;
                    }
                    if (sohead.offsets.strtab == kNoOff && value == si_elf.stringTable())
                    {
                        sohead.offsets.strtab = j;
                        continue;
                    }
                    if (sohead.offsets.symtab == kNoOff && value == si_elf.symbolTable())
                    {
                        sohead.offsets.symtab = j;
                        continue;
                    }
                    if (sohead.offsets.bias == kNoOff && value == si_elf.loadBias() && j != sohead.offsets.base)
                    {
                        sohead.offsets.bias = j;
                        continue;
                    }
                    if (sohead.offsets.strsz == kNoOff && value == si_elf.stringTableSize())
                    {
                        sohead.offsets.strsz = j;
                        continue;
                    }
                }

                if (sohead.offsets.size != kNoOff && sohead.offsets.bias != kNoOff && sohead.offsets.dyn != kNoOff &&
                    sohead.offsets.symtab != kNoOff && sohead.offsets.strtab != kNoOff && sohead.offsets.phdr != kNoOff)
                {
                    // phdr offset might not be 0
                    sohead.soinfo -= sohead.offsets.phdr;
                    sohead.offsets.next = sohead.offsets.phdr + i;

                    uintptr_t si = sohead.soinfo, prev = 0;
                    while (si && KittyMemoryEx::getAddressMap(_pMem->processID(), si, maps).readable)
                    {
                        sohead.soinfo_next_count++;

                        prev = si;

                        if (_pMem->Read(si + sohead.offsets.next, &si, sizeof(uintptr_t)) != sizeof(uintptr_t))
                            break;

                        if (si == prev)
                            break;
                    }

                    break;
                }
            }
        }

        int nmost = 0;
        for (auto &sohead : soheads)
        {
            if (sohead.soinfo_next_count > nmost)
            {
                nmost = sohead.soinfo_next_count;

                _sohead = sohead.soinfo;
                _soheadElf = sohead.elf;
                _soinfo_offsets = sohead.offsets;

                KITTY_LOGD("NativeBridgeScanner: sohead (%d) %p -> %s",
                           sohead.soinfo_next_count,
                           (void *)_sohead,
                           _soheadElf.realPath().c_str());
            }
        }
    }

    if (!_sohead || !_soheadElf.isValid())
    {
        KITTY_LOGD("NativeBridgeScanner: Failed to find emulated solist head.");
        return false;
    }

    KITTY_LOGD("nb_soinfo_base(%zx) | nb_soinfo_size(%zx) | nb_soinfo_bias(%zx)",
               _soinfo_offsets.base,
               _soinfo_offsets.size,
               _soinfo_offsets.bias);
    KITTY_LOGD("nb_soinfo_phdr(%zx, %zx) | nb_soinfo_dyn(%zx)",
               _soinfo_offsets.phdr,
               _soinfo_offsets.phnum,
               _soinfo_offsets.dyn);
    KITTY_LOGD("nb_soinfo_strtab(%zx, %zx) | nb_soinfo_symtab(%zx)",
               _soinfo_offsets.strtab,
               _soinfo_offsets.strsz,
               _soinfo_offsets.symtab);

    KITTY_LOGD("nb_soinfo_next(%zx)", _soinfo_offsets.next);

    _init = _soinfo_offsets.isValid();
    return _init;
}

std::vector<kitty_soinfo_t> NativeBridgeScannerMgr::allSoInfo() const
{
    std::vector<kitty_soinfo_t> infos{};

    if (!_pMem || !_init)
        return infos;

    auto maps = KittyMemoryEx::getAllMaps(_pMem->processID());
    uintptr_t si = _sohead, prev = 0;
    while (si && KittyMemoryEx::getAddressMap(_pMem->processID(), si, maps).readable)
    {
        kitty_soinfo_t info = infoFromSoInfo_(si, maps);
        infos.push_back(info);

        prev = si;

        if (_pMem->Read(si + _soinfo_offsets.next, &si, sizeof(uintptr_t)) != sizeof(uintptr_t))
            break;

        if (si == prev)
            break;
    }
    return infos;
}

kitty_soinfo_t NativeBridgeScannerMgr::findSoInfo(const std::string &name) const
{
    const auto list = allSoInfo();
    for (const auto &it : list)
    {
        if (KittyUtils::String::endsWith(it.realpath, name))
        {
            return it;
        }
    }
    return {};
}

kitty_soinfo_t NativeBridgeScannerMgr::infoFromSoInfo_(uintptr_t si,
                                                       const std::vector<KittyMemoryEx::ProcMap> &maps) const
{
    kitty_soinfo_t info{};

    if (!_pMem || !_init)
        return info;

    std::vector<char> si_buf(KT_SOINFO_BUFFER_SZ, 0);
    if (!_pMem->Read(si, si_buf.data(), KT_SOINFO_BUFFER_SZ))
        return info;

    info.ptr = si;
    info.base = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.base);
    info.size = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.size);
    info.phdr = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.phdr);
    info.phnum = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.phnum);
    info.dyn = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.dyn);
    info.strtab = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.strtab);
    info.symtab = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.symtab);
    info.strsz = _soinfo_offsets.strsz != kitty_soinfo_offsets_t::noff
                     ? *(uintptr_t *)(si_buf.data() + _soinfo_offsets.strsz)
                     : 0;
    info.bias = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.bias);
    info.next = *(uintptr_t *)(si_buf.data() + _soinfo_offsets.next);
    info.e_machine = _soheadElf.header().e_machine;

    uintptr_t start_map_addr = info.base;
    if (start_map_addr == 0)
        start_map_addr = info.bias;
    if (start_map_addr == 0)
        start_map_addr = info.phdr;
    if (start_map_addr == 0)
        start_map_addr = info.dyn;
    if (start_map_addr == 0)
        start_map_addr = info.strtab;
    if (start_map_addr == 0)
        start_map_addr = info.symtab;

    auto si_map = KittyMemoryEx::getAddressMap(_pMem->processID(), start_map_addr, maps);
    if (si_map.isValid())
    {
        info.path = si_map.pathname;
        info.realpath = si_map.pathname;
        if (si_map.offset != 0)
        {
            KittyUtils::Zip::ZipEntryInfo ent{};
            if (KittyUtils::Zip::findEntryInfoByDataOffset(si_map.pathname, si_map.offset, &ent) &&
                !ent.fileName.empty())
            {
                info.realpath += '!';
                info.realpath += ent.fileName;
            }
        }
    }

    return info;
}

#endif // __ANDROID__
