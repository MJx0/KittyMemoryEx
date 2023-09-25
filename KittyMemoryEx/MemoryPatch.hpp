#pragma once

#include "KittyUtils.hpp"
#include "KittyMemoryEx.hpp"
#include "KittyMemOp.hpp"

enum MP_ASM_ARCH
{
    MP_ASM_ARM32 = 0,
    MP_ASM_ARM64,
    MP_ASM_x86,
    MP_ASM_x86_64,
};

class MemoryPatch
{
    friend class MemoryPatchMgr;

private:
    IKittyMemOp *_pMem;

    uintptr_t _address;
    size_t _size;

    std::vector<uint8_t> _orig_code;
    std::vector<uint8_t> _patch_code;

public:
    MemoryPatch();
    ~MemoryPatch();

    MemoryPatch(IKittyMemOp *pMem, uintptr_t absolute_address, const void *patch_code, size_t patch_size);

    bool isValid() const;
    size_t get_PatchSize() const;
    uintptr_t get_TargetAddress() const;

    /*
     * Restores the patch to the original value
     */
    bool Restore();

    /*
     * Applies patch modifications to the target address
     */
    bool Modify();

    /*
     * Returns hex string of the current target address bytes
     */
    std::string get_CurrBytes() const;

    /*
     * Returns hex string of the original bytes
     */
    std::string get_OrigBytes() const;

    /*
     * Returns hex string of the patch bytes
     */
    std::string get_PatchBytes() const;
};

class MemoryPatchMgr
{
private:
    IKittyMemOp *_pMem;

public:
    MemoryPatchMgr() : _pMem(nullptr) {}
    MemoryPatchMgr(IKittyMemOp *pMem) : _pMem(pMem) {}

    MemoryPatch createWithBytes(uintptr_t absolute_address, const void *patch_code, size_t patch_size);
    MemoryPatch createWithBytes(const KittyMemoryEx::ProcMap &map, uintptr_t address, const void *patch_code, size_t patch_size);

    MemoryPatch createWithHex(uintptr_t absolute_address, std::string hex);
    MemoryPatch createWithHex(const KittyMemoryEx::ProcMap &map, uintptr_t address, const std::string &hex);

#ifndef kNO_KEYSTONE
    /**
     * Keystone assembler
     */
    MemoryPatch createWithAsm(uintptr_t absolute_address, MP_ASM_ARCH asm_arch, const std::string &asm_code, uintptr_t asm_address = 0);
    /**
     * Keystone assembler
     */
    MemoryPatch createWithAsm(const KittyMemoryEx::ProcMap &map, uintptr_t address, MP_ASM_ARCH asm_arch, const std::string &asm_code, uintptr_t asm_address = 0);
#endif
};