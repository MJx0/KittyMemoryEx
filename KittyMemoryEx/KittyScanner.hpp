#pragma once

#include <link.h>

#include "KittyUtils.hpp"
#include "KittyMemoryEx.hpp"
#include "KittyMemOp.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <utility>

class KittyScannerMgr
{
private:
    IKittyMemOp *_pMem;

public:
    KittyScannerMgr() : _pMem(nullptr)
    {
    }
    KittyScannerMgr(IKittyMemOp *pMem) : _pMem(pMem)
    {
    }

    /**
     * Search for bytes within a memory range and return all results
     *
     * @param start: search start address
     * @param end: search end address
     * @param bytes: bytes to search
     * @param mask: bytes mask x/?
     *
     * @return vector list of all found bytes addresses
     */
    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end, const char *bytes,
                                        const std::string &mask) const;

    /**
     * Search for bytes within a memory range and return first result
     *
     * @param start: search start address
     * @param end: search end address
     * @param bytes: bytes to search
     * @param mask: bytes mask x/?
     *
     * @return first found bytes address
     */
    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes,
                             const std::string &mask) const;

    /**
     * Search for hex within a memory range and return all results
     *
     * @param start: search start address
     * @param end: search end address
     * @param hex: hex to search
     * @param mask: hex mask x/?
     *
     * @return vector list of all found hex addresses
     */
    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex,
                                      const std::string &mask) const;

    /**
     * Search for hex within a memory range and return first result
     *
     * @param start: search start address
     * @param end: search end address
     * @param hex: hex to search
     * @param mask: hex mask x/?
     *
     * @return first found hex address
     */
    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask) const;

    /**
     * Search for ida pattern within a memory range and return all results
     *
     * @param start: search start address
     * @param end: search end address
     * @param pattern: hex bytes and wildcard "?" ( FF DD ? 99 CC ? 00 )
     *
     * @return vector list of all found pattern addresses
     */
    std::vector<uintptr_t> findIdaPatternAll(const uintptr_t start, const uintptr_t end, const std::string &pattern);

    /**
     * Search for ida pattern within a memory range and return first result
     *
     * @param start: search start address
     * @param end: search end address
     * @param pattern: hex bytes and wildcard "?" ( FF DD ? 99 CC ? 00 )
     *
     * @return first found pattern address
     */
    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string &pattern);

    /**
     * Search for data within a memory range and return all results
     *
     * @param start: search start address
     * @param end: search end address
     * @param data: data to search
     * @param size: data size
     *
     * @return vector list of all found data addresses
     */
    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size) const;

    /**
     * Search for data within a memory range and return first result
     *
     * @param start: search start address
     * @param end: search end address
     * @param data: data to search
     * @param size: data size
     *
     * @return first found data address
     */
    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size) const;
};

#ifdef __ANDROID__

#define KT_SOINFO_BUFFER_SZ 0x250
struct kitty_soinfo_t
{
    uintptr_t ptr = 0;
    uintptr_t base = 0;
    size_t size = 0;
    uintptr_t phdr = 0;
    size_t phnum = 0;
    uintptr_t dyn = 0;
    uintptr_t strtab = 0;
    uintptr_t symtab = 0;
    size_t strsz = 0;
    uintptr_t bias = 0;
    uintptr_t next = 0;
    uint16_t e_machine = 0;
    std::string path;
    std::string realpath;
};

enum class EScanElfType : uint32_t
{
    Any,
    Native,
    Emulated,
};
enum class EScanElfFilter : uint32_t
{
    Any,
    System,
    App,
};

#endif

class ElfScanner
{
    friend class ElfScannerMgr;
    friend class LinkerScannerMgr;
    friend class NativeBeidgeScannerMgr;

protected:
    IKittyMemOp *_pMem;
    uintptr_t _elfBase;
    KT_ElfW(Ehdr) _ehdr;
    uintptr_t _phdr;
    std::vector<KT_ElfW(Phdr)> _phdrs;
    int _loads;
    uintptr_t _loadBias, _loadSize;
    uintptr_t _dynamic;
    std::vector<KT_ElfW(Dyn)> _dynamics;
    uintptr_t _stringTable, _symbolTable;
    size_t _strsz, _syment;
    bool _fixedBySoInfo;
    KittyMemoryEx::ProcMap _baseSegment;
    std::vector<KittyMemoryEx::ProcMap> _segments;
    std::vector<KittyMemoryEx::ProcMap> _bssSegments;
    std::string _filepath;
    std::string _realpath;
    bool _symbols_init;
    bool _dsymbols_init;
    std::unordered_map<std::string, uintptr_t> _symbolsMap;
    std::unordered_map<std::string, uintptr_t> _dsymbolsMap;

public:
    ElfScanner()
        : _pMem(nullptr), _elfBase(0), _phdr(0), _loads(0), _loadBias(0), _loadSize(0), _dynamic(0), _stringTable(0),
          _symbolTable(0), _strsz(0), _syment(0), _fixedBySoInfo(false), _symbols_init(false), _dsymbols_init(false)
    {
    }

    ElfScanner(IKittyMemOp *pMem, uintptr_t elfBase, const std::vector<KittyMemoryEx::ProcMap> &maps);
    ElfScanner(IKittyMemOp *pMem, uintptr_t elfBase)
        : ElfScanner(pMem, elfBase,
                     (pMem ? KittyMemoryEx::getAllMaps(pMem->processID()) : std::vector<KittyMemoryEx::ProcMap>()))
    {
    }

#ifdef __ANDROID__
    ElfScanner(IKittyMemOp *pMem, const kitty_soinfo_t &soinfo, const std::vector<KittyMemoryEx::ProcMap> &maps);
    ElfScanner(IKittyMemOp *pMem, const kitty_soinfo_t &soinfo)
        : ElfScanner(pMem, soinfo,
                     (pMem ? KittyMemoryEx::getAllMaps(pMem->processID()) : std::vector<KittyMemoryEx::ProcMap>()))
    {
    }
#endif

    inline bool isValid() const
    {
        return _elfBase && _loadSize && _phdr && _loadBias;
    }

    inline bool isFixedBySoInfo() const
    {
        return _fixedBySoInfo;
    }

    inline uintptr_t base() const
    {
        return _elfBase;
    }

    inline uintptr_t end() const
    {
        return _elfBase + _loadSize;
    }

    inline KT_ElfW(Ehdr) header() const
    {
        return _ehdr;
    }

    inline uintptr_t phdr() const
    {
        return _phdr;
    }

    inline std::vector<KT_ElfW(Phdr)> programHeaders() const
    {
        return _phdrs;
    }

    inline int loads() const
    {
        return _loads;
    }

    inline uintptr_t loadBias() const
    {
        return _loadBias;
    }

    inline uintptr_t loadSize() const
    {
        return _loadSize;
    }

    inline uintptr_t dynamic() const
    {
        return _dynamic;
    }

    inline std::vector<KT_ElfW(Dyn)> dynamics() const
    {
        return _dynamics;
    }

    inline uintptr_t stringTable() const
    {
        return _stringTable;
    }

    inline uintptr_t symbolTable() const
    {
        return _symbolTable;
    }

    inline size_t stringTableSize() const
    {
        return _strsz;
    }

    inline size_t symbolEntrySize() const
    {
        return _syment;
    }

    // dynamic symbols from DT_SYMTAB
    std::unordered_map<std::string, uintptr_t> symbols();

    // debug symbols from SHT_SYMTAB on disk
    std::unordered_map<std::string, uintptr_t> dsymbols();

    uintptr_t findSymbol(const std::string &symbolName);
    uintptr_t findDebugSymbol(const std::string &symbolName);

    inline KittyMemoryEx::ProcMap baseSegment() const
    {
        return _baseSegment;
    }

    inline std::vector<KittyMemoryEx::ProcMap> segments() const
    {
        return _segments;
    }

    inline std::vector<KittyMemoryEx::ProcMap> bssSegments() const
    {
        return _bssSegments;
    }

    inline std::string filePath() const
    {
        return _filepath;
    }
    inline std::string realPath() const
    {
        return _realpath;
    }
    inline bool isZipped() const
    {
        return _baseSegment.offset != 0;
    }

    // app_proccess DT_DEBUG
    inline bool find_r_debug(r_debug *out) const
    {
        for (auto &it : _dynamics)
        {
            if (it.d_tag == DT_DEBUG && it.d_un.d_val)
            {
                if (out)
                    _pMem->Read(it.d_un.d_val, out, sizeof(r_debug));

                return true;
            }
        }
        return false;
    }
};

class ElfScannerMgr
{
    friend class NativeBeidgeScannerMgr;

protected:
    IKittyMemOp *_pMem;
    ElfScanner _programElf;
    std::unordered_map<uintptr_t, ElfScanner> _cached_elfs;

public:
    ElfScannerMgr() : _pMem(nullptr)
    {
    }
    ElfScannerMgr(IKittyMemOp *pMem) : _pMem(pMem)
    {
    }

    inline ElfScanner createWithBase(uintptr_t elfBase) const
    {
        return !_pMem ? ElfScanner() : ElfScanner(_pMem, elfBase);
    }
    inline ElfScanner createWithMap(const KittyMemoryEx::ProcMap &map) const
    {
        return !_pMem ? ElfScanner() : ElfScanner(_pMem, map.startAddress);
    }
#ifdef __ANDROID__
    inline ElfScanner createWithSoInfo(const kitty_soinfo_t &soinfo) const
    {
        return !_pMem ? ElfScanner() : ElfScanner(_pMem, soinfo);
    }
#endif

    /**
     * Validate ELF
     * @param elfBase: ELF start address
     */
    bool isValidELF(uintptr_t elfBase) const;

    inline bool isElfNative(const ElfScanner &elf)
    {
        int a = getProgramElf().header().e_machine, b = elf.header().e_machine;
        return a != 0 && b != 0 && a == b;
    }

    inline bool isElfEmulated(const ElfScanner &elf)
    {
        int a = getProgramElf().header().e_machine, b = elf.header().e_machine;
        return a != 0 && b != 0 && a != b;
    }

    /**
     * /proc/[pid]/exe
     */
    ElfScanner &getProgramElf();

#ifdef __ANDROID__
    /**
     * Fetch all in-memory loaded ELFs
     */
    std::vector<ElfScanner> getAllELFs(EScanElfType type = EScanElfType::Any,
                                       EScanElfFilter filter = EScanElfFilter::Any);

    /**
     * Find in-memory loaded ELF with name
     */
    ElfScanner findElf(const std::string &path, EScanElfType type = EScanElfType::Any,
                       EScanElfFilter filter = EScanElfFilter::Any);

    /**
     * lookup symbol name in all loaded ELFs
     * @return a vector of symbol absolute address and the ELF where the symbol was found in
     */
    std::vector<std::pair<uintptr_t, ElfScanner>> findSymbolAll(const std::string &symbolName,
                                                                EScanElfType type = EScanElfType::Any,
                                                                EScanElfFilter filter = EScanElfFilter::Any);
#else
    /**
     * Fetch all in-memory loaded ELFs
     */
    std::vector<ElfScanner> getAllELFs();

    /**
     * Find in-memory loaded ELF with name
     */
    ElfScanner findElf(const std::string &path);

    /**
     * lookup symbol name in all loaded ELFs
     * @return a vector of symbol absolute address and the ELF where the symbol was found in
     */
    std::vector<std::pair<uintptr_t, ElfScanner>> findSymbolAll(const std::string &symbolName);
#endif

    /**
     * Find remote address of local symbol.
     */
    uintptr_t findRemoteSymbol(const std::string &local_sym_name, uintptr_t local_sym_addr);
};

#ifdef __ANDROID__
struct kitty_linker_syms_t
{
    uintptr_t solist = 0;
    uintptr_t somain = 0;
    uintptr_t sonext = 0;
};

struct kitty_soinfo_offsets_t
{
    uintptr_t base = 0;
    uintptr_t size = 0;
    uintptr_t phdr = 0;
    uintptr_t phnum = 0;
    uintptr_t dyn = 0;
    uintptr_t strtab = 0;
    uintptr_t symtab = 0;
    uintptr_t strsz = 0;
    uintptr_t bias = 0;
    uintptr_t next = 0;
};

class LinkerScannerMgr : public ElfScanner
{
private:
    kitty_linker_syms_t _linker_syms;
    kitty_soinfo_offsets_t _soinfo_offsets;
    bool _init;

public:
    LinkerScannerMgr() : ElfScanner(), _init(false)
    {
        memset(&_linker_syms, 0, sizeof(_linker_syms));
        memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
    }

    LinkerScannerMgr(IKittyMemOp *pMem, const ElfScanner &linkerElf);
    LinkerScannerMgr(IKittyMemOp *pMem, uintptr_t linkerBase);

    bool init();
    
    inline ElfScanner *asELF() const
    {
        return (ElfScanner *)this;
    }

    inline kitty_linker_syms_t linker_offsets() const
    {
        return _linker_syms;
    }

    inline kitty_soinfo_offsets_t soinfo_offsets() const
    {
        return _soinfo_offsets;
    }

    inline uintptr_t solist() const
    {
        if (!isValid() || !_linker_syms.solist)
            return 0;

        uintptr_t value = 0;
        return _pMem->Read(_linker_syms.solist, &value, sizeof(uintptr_t)) == sizeof(uintptr_t) ? value : 0;
    }

    inline uintptr_t somain() const
    {
        if (!isValid() || !_linker_syms.somain)
            return 0;

        uintptr_t value = 0;
        return _pMem->Read(_linker_syms.somain, &value, sizeof(uintptr_t)) == sizeof(uintptr_t) ? value : 0;
    }

    inline uintptr_t sonext() const
    {
        if (!isValid() || !_linker_syms.sonext)
            return 0;

        uintptr_t value = 0;
        return _pMem->Read(_linker_syms.sonext, &value, sizeof(uintptr_t)) == sizeof(uintptr_t) ? value : 0;
    }

    inline kitty_soinfo_t somainInfo() const
    {
        if (!isValid() || !_linker_syms.somain)
            return {};

        return infoFromSoInfo_(somain(), KittyMemoryEx::getAllMaps(_pMem->processID()));
    }

    inline kitty_soinfo_t sonextInfo() const
    {
        if (!isValid())
            return {};

        return infoFromSoInfo_(sonext(), KittyMemoryEx::getAllMaps(_pMem->processID()));
    }

    std::vector<kitty_soinfo_t> allSoInfo() const;

    kitty_soinfo_t findSoInfo(const std::string &name) const;

private:
    kitty_soinfo_t infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemoryEx::ProcMap> &maps) const;
};

enum KT_JNICallType
{
    KT_JNICallTypeRegular = 1,
    KT_JNICallTypeCriticalNative = 2,
};

enum KT_NativeBridgeImplementationVersion
{
    // first version, not used.
    KT_NB_DEFAULT_VERSION = 1,
    // The version which signal semantic is introduced.
    KT_NB_SIGNAL_VERSION = 2,
    // The version which namespace semantic is introduced.
    KT_NB_NAMESPACE_VERSION = 3,
    // The version with vendor namespaces
    KT_NB_VENDOR_NAMESPACE_VERSION = 4,
    // The version with runtime namespaces
    KT_NB_RUNTIME_NAMESPACE_VERSION = 5,
    // The version with pre-zygote-fork hook to support app-zygotes.
    KT_NB_PRE_ZYGOTE_FORK_VERSION = 6,
    // The version with critical_native support
    KT_NB_CRITICAL_NATIVE_SUPPORT_VERSION = 7,
    // The version with native bridge detection fallback for function pointers
    KT_NB_IDENTIFY_NATIVELY_BRIDGED_FUNCTION_POINTERS_VERSION = 8,
};

struct nbItf_data_t
{
    inline nbItf_data_t()
    {
        memset(this, 0, sizeof(nbItf_data_t));
    }

    int version;
#ifdef __LP64__
    uint32_t pad1;
#endif
    bool (*initialize)(const void *runtime_cbs, const char *private_dir, const char *instruction_set);
    void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    bool (*isSupported)(const char *libpath);
    const void *(*getAppEnv)(const char *instruction_set);
    bool (*isCompatibleWith)(uint32_t bridge_version);
    void *(*getSignalHandler)(int signal);
    int (*unloadLibrary)(void *handle);
    const char *(*getError)();
    bool (*isPathSupported)(const char *library_path);
    bool (*initAnonymousNamespace)(const char *public_ns_sonames, const char *anon_ns_library_path);
    void *(*createNamespace)(const char *name, const char *ld_library_path, const char *default_library_path,
                             uint64_t type, const char *permitted_when_isolated_path, void *parent_ns);
    bool (*linkNamespaces)(void *from, void *to, const char *shared_libs_sonames);
    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
    void *(*getVendorNamespace)();
    void *(*getExportedNamespace)(const char *name);
    void (*preZygoteFork)();
    void *(*getTrampolineWithJNICallType)(void *handle, const char *name, const char *shorty, uint32_t len,
                                          enum KT_JNICallType jni_call_type);
    void *(*getTrampolineForFunctionPointer)(const void *method, const char *shorty, uint32_t len,
                                             enum KT_JNICallType jni_call_type);
    bool (*isNativeBridgeFunctionPointer)(const void *method);

    inline static size_t GetStructSize(int version)
    {
        switch (version)
        {
        case KT_NB_SIGNAL_VERSION:
            return sizeof(uintptr_t) * 8;
        case KT_NB_NAMESPACE_VERSION:
            return sizeof(uintptr_t) * 15;
        case KT_NB_VENDOR_NAMESPACE_VERSION:
            return sizeof(uintptr_t) * 16;
        case KT_NB_RUNTIME_NAMESPACE_VERSION:
            return sizeof(uintptr_t) * 17;
        case KT_NB_PRE_ZYGOTE_FORK_VERSION:
            return sizeof(uintptr_t) * 18;
        case KT_NB_CRITICAL_NATIVE_SUPPORT_VERSION:
            return sizeof(uintptr_t) * 19;
        case KT_NB_IDENTIFY_NATIVELY_BRIDGED_FUNCTION_POINTERS_VERSION:
            return sizeof(uintptr_t) * 21;
        }
        return 0;
    }
};

class NativeBridgeScannerMgr
{
private:
    IKittyMemOp *_pMem;
    KittyScannerMgr *_memScanner;
    ElfScannerMgr *_elfScanner;
    ElfScanner _nbElf, _nbImplElf, _sodlElf;
    uintptr_t _sodl;
    kitty_soinfo_offsets_t _soinfo_offsets;
    bool _init;
    bool _isHoudini;

    uintptr_t _nbItf;
    size_t _nbItf_data_size;
    nbItf_data_t _nbItf_data;

public:
    bool (*fnNativeBridgeInitialized)();

    NativeBridgeScannerMgr()
        : _pMem(nullptr), _memScanner(nullptr), _elfScanner(nullptr), _sodl(0), _init(false), _isHoudini(false),
          _nbItf(0), _nbItf_data_size(0), fnNativeBridgeInitialized(nullptr)
    {
        memset(&_nbItf_data, 0, sizeof(_nbItf_data));
        memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
    }

    NativeBridgeScannerMgr(IKittyMemOp *pMem, KittyScannerMgr *memScanner, ElfScannerMgr *elfScanner);

    bool init();

    inline bool isValid() const
    {
        return _init;
    }

    inline kitty_soinfo_offsets_t soinfo_offsets() const
    {
        return _soinfo_offsets;
    }

    inline ElfScanner &nbElf()
    {
        return _nbElf;
    }

    inline ElfScanner &nbImplElf()
    {
        return _nbImplElf;
    }
    inline ElfScanner &sodlElf()
    {
        return _sodlElf;
    }

    inline bool isHoudini() const
    {
        return _isHoudini;
    }

    inline uintptr_t sodl() const
    {
        return _sodl;
    }

    inline kitty_soinfo_t sodlInfo() const
    {
        if (!_pMem || !_sodl)
            return {};

        return infoFromSoInfo_(_sodl, KittyMemoryEx::getAllMaps(_pMem->processID()));
    }

    std::vector<kitty_soinfo_t> allSoInfo() const;

    kitty_soinfo_t findSoInfo(const std::string &name) const;

    inline size_t nbItfDataSize() const
    {
        return _nbItf_data_size;
    }

    inline nbItf_data_t nbItfData() const
    {
        return _nbItf_data;
    }

private:
    kitty_soinfo_t infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemoryEx::ProcMap> &maps) const;
};

#endif // __ANDROID__
