#pragma once

#include "KittyUtils.hpp"
#include "KittyMemoryEx.hpp"
#include "KittyMemOp.hpp"

class KittyScannerMgr
{
private:
    IKittyMemOp *_pMem;

public:
    KittyScannerMgr() : _pMem(nullptr) {}
    KittyScannerMgr(IKittyMemOp *pMem) : _pMem(pMem) {}

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
    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string &mask) const;

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
    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string &mask) const;

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
    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask) const;

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
    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string& pattern);

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

class ElfScanner
{
    friend class ElfScannerMgr;

private:
    IKittyMemOp *_pMem;
    uintptr_t _elfBase;
    ElfW_(Ehdr) _ehdr;
    uintptr_t _phdr;
    std::vector<ElfW_(Phdr)> _phdrs;
    int _loads;
    uintptr_t _loadBias, _loadSize;
    uintptr_t _bss;
    size_t _bssSize;
    uintptr_t _dynamic;
    std::vector<ElfW_(Dyn)> _dynamics;
    uintptr_t _stringTable, _symbolTable;
    size_t _strsz, _syment;
    bool _symbols_init;
    std::vector<std::pair<uintptr_t, std::string>> _symbols;
    KittyMemoryEx::ProcMap _base_segment;
    std::vector<KittyMemoryEx::ProcMap> _segments;

public:
    ElfScanner() : _pMem(nullptr), _elfBase(0), _phdr(0), _loads(0), _loadBias(0), _loadSize(0), _bss(0), _bssSize(0),
                   _dynamic(0), _stringTable(0), _symbolTable(0), _strsz(0), _syment(0), _symbols_init(false) {}
    ElfScanner(IKittyMemOp *pMem, uintptr_t elfBase);

    inline bool isValid() const
    {
        return _loads && !_phdrs.empty() && _loadBias && _loadSize &&
               !_dynamics.empty() && _stringTable && _symbolTable && _strsz && _syment;
    }

    inline uintptr_t base() const { return _elfBase; }

    inline uintptr_t end() const { return _elfBase + _loadSize; }

    inline ElfW_(Ehdr) header() const { return _ehdr; }

    inline uintptr_t phdr() const { return _phdr; }

    inline std::vector<ElfW_(Phdr)> programHeaders() const { return _phdrs; }

    inline int loads() const { return _loads; }

    inline uintptr_t loadBias() const { return _loadBias; }

    inline uintptr_t loadSize() const { return _loadSize; }

    inline uintptr_t bss() const { return _bss; }
    
    inline size_t bssSize() const { return _bssSize; }

    inline uintptr_t dynamic() const { return _dynamic; }

    inline std::vector<ElfW_(Dyn)> dynamics() const { return _dynamics; }

    inline uintptr_t stringTable() const { return _stringTable; }

    inline uintptr_t symbolTable() const { return _symbolTable; }

    inline size_t stringTableSize() const { return _strsz; }

    inline size_t symbolEntrySize() const { return _syment; }

    std::vector<std::pair<uintptr_t, std::string>> symbols();

    // retuns the absolute address of symbol in dynstr
    uintptr_t findSymbol(const std::string &symbolName);

    inline KittyMemoryEx::ProcMap baseSegment() const { return _base_segment; }

    inline std::vector<KittyMemoryEx::ProcMap> segments() const { return _segments; }

    inline std::string filePath() const { return _base_segment.pathname; }
};

class ElfScannerMgr
{
private:
    IKittyMemOp *_pMem;

public:
    ElfScannerMgr() : _pMem(nullptr) {}
    ElfScannerMgr(IKittyMemOp *pMem) : _pMem(pMem) {}

    inline ElfScanner createWithBase(uintptr_t elfBase) const
    {
        return !_pMem ? ElfScanner() : ElfScanner(_pMem, elfBase);
    }
    inline ElfScanner createWithMap(const KittyMemoryEx::ProcMap &map) const
    {
        return !_pMem ? ElfScanner() : ElfScanner(_pMem, map.startAddress);
    }
};