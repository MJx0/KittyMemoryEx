#include "MemoryBackup.hpp"

MemoryBackup::MemoryBackup()
{
  _pMem = nullptr;
  _address = 0;
  _size = 0;
  _orig_code.clear();
}

MemoryBackup::~MemoryBackup()
{
  // clean up
  _orig_code.clear();
  _orig_code.shrink_to_fit();
}

MemoryBackup::MemoryBackup(IKittyMemOp *pMem, uintptr_t absolute_address, size_t backup_size)
{
  _pMem = nullptr;
  _address = 0;
  _size = 0;
  _orig_code.clear();

  if (!pMem || !absolute_address || !backup_size)
    return;

  _pMem = pMem;
  _address = absolute_address;
  _size = backup_size;
  _orig_code.resize(backup_size);

  // backup current content
  _pMem->Read(_address, &_orig_code[0], _size);
}

bool MemoryBackup::isValid() const
{
  return (_pMem && _address && _size && _orig_code.size() == _size);
}

size_t MemoryBackup::get_BackupSize() const
{
  return _size;
}

uintptr_t MemoryBackup::get_TargetAddress() const
{
  return _address;
}

bool MemoryBackup::Restore()
{
  if (!isValid())
    return false;

  return _pMem->Write(_address, &_orig_code[0], _size);
}

std::string MemoryBackup::get_CurrBytes() const
{
  if (!isValid())
    return "";

  std::vector<uint8_t> buffer(_size);
  _pMem->Read(_address, &buffer[0], _size);

  return KittyUtils::data2Hex(&buffer[0], _size);
}

std::string MemoryBackup::get_OrigBytes() const
{
  if (!isValid())
    return "";

  return KittyUtils::data2Hex(&_orig_code[0], _orig_code.size());
}

/* ============================== MemoryBackupMgr ============================== */

MemoryBackup MemoryBackupMgr::createBackup(uintptr_t absolute_address, size_t backup_size)
{
  return MemoryBackup(_pMem, absolute_address, backup_size);
}

MemoryBackup MemoryBackupMgr::createBackup(const KittyMemoryEx::ProcMap &map, uintptr_t address, size_t backup_size)
{
  if (!map.isValid() || !address || !backup_size)
    return MemoryBackup();

  return MemoryBackup(_pMem, map.startAddress + address, backup_size);
}