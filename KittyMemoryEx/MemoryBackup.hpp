#pragma once

#include "KittyUtils.hpp"
#include "KittyMemoryEx.hpp"
#include "KittyMemOp.hpp"

class MemoryBackup
{
    friend class MemoryBackupMgr;

private:
    IKittyMemOp *_pMem;

    uintptr_t _address;
    size_t _size;

    std::vector<uint8_t> _orig_code;

public:
    MemoryBackup();
    ~MemoryBackup();

    MemoryBackup(IKittyMemOp *pMem, uintptr_t absolute_address, size_t backup_size);

    bool isValid() const;
    size_t get_BackupSize() const;
    uintptr_t get_TargetAddress() const;

    /*
     * Restores backup code
     */
    bool Restore();

    /*
     * Returns hex string of the current target address bytes
     */
    std::string get_CurrBytes() const;

    /*
     * Returns hex string of the original bytes
     */
    std::string get_OrigBytes() const;
};

class MemoryBackupMgr
{
private:
    IKittyMemOp *_pMem;

public:
    MemoryBackupMgr() : _pMem(nullptr) {}
    MemoryBackupMgr(IKittyMemOp *pMem) : _pMem(pMem) {}

    MemoryBackup createBackup(uintptr_t absolute_address, size_t backup_size);
    MemoryBackup createBackup(const KittyMemoryEx::ProcMap &map, uintptr_t address, size_t backup_size);
};