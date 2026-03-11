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
                                     const iovec *lvec,
                                     unsigned long liovcnt,
                                     const iovec *rvec,
                                     unsigned long riovcnt,
                                     unsigned long flags)
{
    return syscall(syscall_rpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

static ssize_t call_process_vm_writev(pid_t pid,
                                      const iovec *lvec,
                                      unsigned long liovcnt,
                                      const iovec *rvec,
                                      unsigned long riovcnt,
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
        _lastErrno = ESRCH;
        KITTY_LOGE("KittyMemSys: Invalid PID.");
        return false;
    }

    errno = 0;
    ssize_t rt = syscall(syscall_rpmv_n, 0, 0, 0, 0, 0, 0);
    if (rt == -1 && errno == ENOSYS)
    {
        _lastErrno = ENOSYS;
        KITTY_LOGE("KittyMemSys: syscall readv/writev not supported.");
        return false;
    }

    _pid = pid;
    return true;
}

size_t KittyMemSys::Read(uintptr_t address, void *buffer, size_t len)
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    struct iovec lvec{.iov_base = buffer, .iov_len = 0};
    struct iovec rvec{.iov_base = KittyUtils::untagHeepPtr(reinterpret_cast<void *>(address)), .iov_len = 0};

    ssize_t n = 0;
    size_t nbytes = 0, remaining = len;
    bool page_mode = false;
    do
    {
        size_t remaining_or_pglen = remaining;
        if (page_mode)
            remaining_or_pglen = std::min(KT_PAGE_LEN(rvec.iov_base), remaining);

        lvec.iov_len = remaining_or_pglen;
        rvec.iov_len = remaining_or_pglen;

        errno = 0;
        n = KT_EINTR_RETRY(call_process_vm_readv(_pid, &lvec, 1, &rvec, 1, 0));
        if (n > 0)
        {
            remaining -= n;
            nbytes += n;
            lvec.iov_base = reinterpret_cast<char *>(lvec.iov_base) + n;
            rvec.iov_base = reinterpret_cast<char *>(rvec.iov_base) + n;
        }
        else
        {
            if (n == -1)
            {
                _lastErrno = errno;
                if (_lastErrno != EFAULT && _lastErrno != EIO && _lastErrno != EINVAL)
                    break;
            }
            if (page_mode)
            {
                remaining -= remaining_or_pglen;
                lvec.iov_base = reinterpret_cast<char *>(lvec.iov_base) + remaining_or_pglen;
                rvec.iov_base = reinterpret_cast<char *>(rvec.iov_base) + remaining_or_pglen;
            }
        }
        page_mode = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return nbytes;
}

size_t KittyMemSys::Write(uintptr_t address, void *buffer, size_t len)
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    struct iovec lvec{.iov_base = buffer, .iov_len = 0};
    struct iovec rvec{.iov_base = KittyUtils::untagHeepPtr(reinterpret_cast<void *>(address)), .iov_len = 0};

    ssize_t n = 0;
    size_t nbytes = 0, remaining = len;
    bool write_one_page = false;
    do
    {
        size_t remaining_or_pglen = remaining;
        if (write_one_page)
            remaining_or_pglen = std::min(KT_PAGE_LEN(rvec.iov_base), remaining);

        lvec.iov_len = remaining_or_pglen;
        rvec.iov_len = remaining_or_pglen;

        errno = 0;
        n = KT_EINTR_RETRY(call_process_vm_writev(_pid, &lvec, 1, &rvec, 1, 0));
        if (n > 0)
        {
            remaining -= n;
            nbytes += n;
            lvec.iov_base = reinterpret_cast<char *>(lvec.iov_base) + n;
            rvec.iov_base = reinterpret_cast<char *>(rvec.iov_base) + n;
        }
        else
        {
            if (n == -1)
            {
                _lastErrno = errno;
                if (_lastErrno != EFAULT && _lastErrno != EIO && _lastErrno != EINVAL)
                    break;
            }
            if (write_one_page)
            {
                remaining -= remaining_or_pglen;
                lvec.iov_base = reinterpret_cast<char *>(lvec.iov_base) + remaining_or_pglen;
                rvec.iov_base = reinterpret_cast<char *>(rvec.iov_base) + remaining_or_pglen;
            }
        }
        write_one_page = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return nbytes;
}

/* =================== KittyMemIO =================== */

bool KittyMemIO::init(pid_t pid)
{
    if (pid < 1)
    {
        _lastErrno = ESRCH;
        KITTY_LOGE("KittyMemIO: Invalid PID.");
        return false;
    }

    _pid = pid;

    char memPath[256] = {0};
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", _pid);
    _pMem = std::make_unique<KittyIOFile>(memPath, O_RDWR);
    if (!_pMem->open())
    {
        _lastErrno = _pMem->lastError();
        KITTY_LOGE("Couldn't open mem file %s, error=%s", _pMem->path().c_str(), _pMem->lastStrError().c_str());
        return false;
    }

    return _pid > 0 && _pMem.get();
}

size_t KittyMemIO::Read(uintptr_t address, void *buffer, size_t len)
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    address = KittyUtils::untagHeepPtr(address);

    ssize_t n = 0;
    size_t nbytes = 0, remaining = len;
    bool page_mode = false;
    do
    {
        size_t remaining_or_pglen = remaining;
        if (page_mode)
            remaining_or_pglen = std::min(KT_PAGE_LEN(address), remaining);

        errno = 0;
        n = _pMem->pread(address, buffer, remaining_or_pglen);
        if (n > 0)
        {
            remaining -= n;
            nbytes += n;
            address += n;
            buffer = reinterpret_cast<char *>(buffer) + n;
        }
        else
        {
            if (n == -1)
            {
                _lastErrno = errno;
                if (_lastErrno != EFAULT && _lastErrno != EIO && _lastErrno != EINVAL)
                    break;
            }

            if (page_mode)
            {
                remaining -= remaining_or_pglen;
                address += remaining_or_pglen;
                buffer = reinterpret_cast<char *>(buffer) + remaining_or_pglen;
            }
        }
        page_mode = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return nbytes;
}

size_t KittyMemIO::Write(uintptr_t address, void *buffer, size_t len)
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    address = KittyUtils::untagHeepPtr(address);

    ssize_t n = 0;
    size_t nbytes = 0, remaining = len;
    bool page_mode = false;
    do
    {
        size_t remaining_or_pglen = remaining;
        if (page_mode)
            remaining_or_pglen = std::min(KT_PAGE_LEN(address), remaining);

        errno = 0;
        n = _pMem->pwrite(address, buffer, remaining_or_pglen);
        if (n > 0)
        {
            remaining -= n;
            nbytes += n;
            address += n;
            buffer = reinterpret_cast<char *>(buffer) + n;
        }
        else
        {
            if (n == -1)
            {
                _lastErrno = errno;
                if (_lastErrno != EFAULT && _lastErrno != EIO && _lastErrno != EINVAL)
                    break;
            }

            if (page_mode)
            {
                remaining -= remaining_or_pglen;
                address += remaining_or_pglen;
                buffer = reinterpret_cast<char *>(buffer) + remaining_or_pglen;
            }
        }
        page_mode = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return nbytes;
}