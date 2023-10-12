#include "KittyMemOp.hpp"
#include <cerrno>

// process_vm_readv & process_vm_writev
#if defined(__aarch64__)
#define syscall_rpmv_n 270
#define syscall_wpmv_n 271
#elif defined(__arm__)
#define syscall_rpmv_n 376
#define syscall_wpmv_n 377
#elif defined(__i386__)
#define syscall_rpmv_n 347
#define syscall_wpmv_n 348
#elif defined(__x86_64__)
#define syscall_rpmv_n 310
#define syscall_wpmv_n 311
#else
#error "Unsupported ABI"
#endif

static ssize_t call_process_vm_readv(pid_t pid,
                                     const iovec *lvec, unsigned long liovcnt,
                                     const iovec *rvec, unsigned long riovcnt,
                                     unsigned long flags)
{
    return syscall(syscall_rpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

static ssize_t call_process_vm_writev(pid_t pid,
                                      const iovec *lvec, unsigned long liovcnt,
                                      const iovec *rvec, unsigned long riovcnt,
                                      unsigned long flags)
{
    return syscall(syscall_wpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

/* =================== IKittyMemOp =================== */

std::string IKittyMemOp::ReadStr(uintptr_t address, size_t maxLen)
{
    std::vector<char> chars(maxLen);

    if (!Read(address, &chars[0], maxLen))
        return "";

    std::string str = "";
    for (size_t i = 0; i < chars.size(); i++)
    {
        if (chars[i] == '\0')
            break;

        str.push_back(chars[i]);
    }

    if ((int)str[0] == 0 && str.size() == 1)
        return "";

    return str;
}

bool IKittyMemOp::WriteStr(uintptr_t address, std::string str)
{
    size_t len = str.length() + 1; // extra for \0;
    return Write(address, &str[0], len) == len;
}

/* =================== KittyMemSys =================== */

bool KittyMemSys::init(pid_t pid)
{
    if (pid < 1)
    {
        KITTY_LOGE("KittyMemSys: Invalid PID.");
        return false;
    }

    errno = 0;
    ssize_t rt = syscall(syscall_rpmv_n, 0, 0, 0, 0, 0, 0);
    if (rt == -1 && errno == ENOSYS)
    {
        KITTY_LOGE("KittyMemSys: syscall not supported.");
        return false;
    }

    _pid = pid;
    return true;
}

size_t KittyMemSys::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    struct iovec local[1];
    local[0].iov_base = buffer;
    local[0].iov_len = len;

    struct iovec remote[1];
    remote[0].iov_base = (void *)address;
    remote[0].iov_len = len;

    errno = 0;
    ssize_t bytes = KT_EINTR_RETRY(call_process_vm_readv(_pid, &local[0], 1, &remote[0], 1, 0));
    if (bytes == -1)
    {
        int err = errno;
        switch (err)
        {
        case EPERM:
            KITTY_LOGE("Read: Can't access the address space of process ID (%d).", _pid);
            break;
        case ESRCH:
            KITTY_LOGE("Read: No process with ID (%d) exists.", _pid);
            break;
        case ENOMEM:
            KITTY_LOGE("Read: Could not allocate memory for internal copies of the iovec structures.");
            break;
        default:
            KITTY_LOGD("Read: address (%p) with len (0x%zx), error=%d | %s.", (void *)address, len, err, strerror(err));
            break;
        }
    }
    return bytes > 0 ? bytes : 0;
}

size_t KittyMemSys::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    iovec local[1];
    local[0].iov_base = buffer;
    local[0].iov_len = len;

    iovec remote[1];
    remote[0].iov_base = (void *)address;
    remote[0].iov_len = len;

    errno = 0;
    ssize_t bytes = KT_EINTR_RETRY(call_process_vm_writev(_pid, &local[0], 1, &remote[0], 1, 0));
    if (bytes == -1)
    {
        int err = errno;
        switch (err)
        {
        case EPERM:
            KITTY_LOGE("Write: Can't access the address space of process ID (%d).", _pid);
            break;
        case ESRCH:
            KITTY_LOGE("Write: No process with ID (%d) exists.", _pid);
            break;
        case ENOMEM:
            KITTY_LOGE("Write: Could not allocate memory for internal copies of the iovec structures.");
            break;
        default:
            KITTY_LOGD("Write: address (%p) with len (0x%zx), error=%d | %s.", (void *)address, len, err, strerror(err));
            break;
        }
    }
    return bytes > 0 ? bytes : 0;
}

/* =================== KittyMemIO =================== */

bool KittyMemIO::init(pid_t pid)
{
    if (pid < 1)
    {
        KITTY_LOGE("KittyMemIO: Invalid PID.");
        return false;
    }

    _pid = pid;

    char memPath[256] = {0};
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", _pid);
    _pMem = std::make_unique<KittyIOFile>(memPath, O_RDWR);
    if (!_pMem->Open())
    {
        KITTY_LOGE("Couldn't open mem file %s, error=%s", _pMem->Path().c_str(), _pMem->lastStrError().c_str());
        return false;
    }

    return _pid > 0 && _pMem.get();
}

size_t KittyMemIO::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    ssize_t bytes = _pMem->Read(address, buffer, len);
    return bytes > 0 ? bytes : 0;
}

size_t KittyMemIO::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    ssize_t bytes = _pMem->Write(address, buffer, len);
    return bytes > 0 ? bytes : 0;
}