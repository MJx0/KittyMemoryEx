#include "KittyMemOp.hpp"

/**
 * @brief Amount of contiguous successfully processed memory before retrying
 *        a large continuous transfer.
 *
 * After entering page mode, once this amount of memory has been successfully
 * processed, the operation attempts to return to normal large-range mode.
 */
static constexpr size_t KT_RETRY_NORMAL_AFTER = 64 * 1024;


/**
 * @brief Internal transfer state.
 *
 * Used by KittyMemoryTransfer() to switch between continuous transfers and
 * page-by-page transfers.
 */
enum class KTTransferState
{
    /**
     * @brief Attempt to process the entire remaining range.
     */
    Normal,


    /**
     * @brief Process memory one page at a time.
     */
    Page
};

/**
 * @brief Performs a memory transfer with optional inaccessible-page handling.
 *
 * This helper implements the common logic shared by memory operations backends.
 *
 * Behavior:
 *
 * - MemMode::Normal:
 *   Performs a single continuous transfer attempt.
 *
 * - MemMode::SkipInaccessiblePages:
 *   Attempts a continuous transfer first. If it fails, switches to page mode
 *   and skips inaccessible pages. After 64 KiB of contiguous successful
 *   transfers, it retries continuous mode.
 *
 * @tparam T Callable type implementing the actual read/write operation.
 *
 * @param address Starting memory address.
 * @param buffer Buffer used for the transfer.
 * @param len Number of bytes to transfer.
 * @param mode Transfer behavior.
 * @param operation Backend memory operation callback.
 *
 * @return Number of bytes successfully transferred.
 */
template <typename T>
static size_t KittyMemoryTransfer(uintptr_t address, void *buffer, size_t len, MemMode mode, T &&operation)
{
    if (!address || !buffer || !len)
        return 0;

    size_t total = 0;

    KTTransferState state = KTTransferState::Normal;

    size_t contiguousSuccess = 0;

    while (len)
    {
        size_t requestSize = len;

        if (state == KTTransferState::Page)
            requestSize = std::min(KT_PAGE_REMAIN(address), len);

        ssize_t sn = static_cast<ssize_t>(operation(address, buffer, requestSize));
        if (sn < 0)
        {
            switch (sn)
            {
            case -ESRCH:  // process exited
            case -EBADF:  // invalid fd
            case -EPERM:  // permission lost
            case -EINVAL: // invalid arguments
                return total;
            default:
                break;
            }
        }

        size_t n = sn < 0 ? 0 : static_cast<size_t>(sn);

        if (n > 0)
        {
            total += n;

            address += n;
            buffer = static_cast<char *>(buffer) + n;
            len -= n;

            if (state == KTTransferState::Page)
            {
                contiguousSuccess += n;

                if (contiguousSuccess >= KT_RETRY_NORMAL_AFTER)
                {
                    state = KTTransferState::Normal;
                    contiguousSuccess = 0;
                }
            }

            // partial success means remaining bytes are still pending
            if (n != requestSize && mode == MemMode::Normal)
            {
                break;
            }

            continue;
        }

        /*
         * No bytes transferred.
         */

        if (mode == MemMode::Normal)
            break;

        if (state == KTTransferState::Normal)
        {
            /*
             * Large request failed.
             * Switch to page scanning.
             */
            state = KTTransferState::Page;
            contiguousSuccess = 0;
            continue;
        }

        /*
         * Page failed.
         * Skip it.
         */
        size_t skip = std::min(KT_PAGE_REMAIN(address), len);

        address += skip;
        buffer = static_cast<char *>(buffer) + skip;
        len -= skip;

        contiguousSuccess = 0;
    }

    return total;
}

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

std::string IKittyMemOp::ReadUTF8(uintptr_t address, size_t maxLen)
{
    std::string result(maxLen + 1, '\0');
    if (Read(address, result.data(), maxLen) == 0)
        return "";

    const size_t nullPos = result.find('\0');
    if (nullPos != std::string::npos)
        result.resize(nullPos);

    return result;
}

std::u16string IKittyMemOp::ReadUTF16(uintptr_t address, size_t maxLen)
{
    std::u16string result(maxLen + 1, u'\0');
    if (Read(address, result.data(), maxLen * sizeof(char16_t)) == 0)
        return u"";

    const size_t nullPos = result.find(u'\0');
    if (nullPos != std::u16string::npos)
        result.resize(nullPos);

    return result;
}

std::u32string IKittyMemOp::ReadUTF32(uintptr_t address, size_t maxLen)
{
    std::u32string result(maxLen + 1, U'\0');
    if (Read(address, result.data(), maxLen * sizeof(char32_t)) == 0)
        return U"";

    const size_t nullPos = result.find(U'\0');
    if (nullPos != std::u32string::npos)
        result.resize(nullPos);

    return result;
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

size_t KittyMemSys::Read(uintptr_t address, void *buffer, size_t len, MemMode mode)
{
    address = KittyUtils::untagPointer(address);

    return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
        errno = 0;

        iovec local{.iov_base = buf, .iov_len = size};
        iovec remote{.iov_base = reinterpret_cast<void *>(addr), .iov_len = size};

        ssize_t n = KT_EINTR_RETRY(call_process_vm_readv(_pid, &local, 1, &remote, 1, 0));

        if (n < 0)
            _lastErrno = errno;

        return n < 0 ? static_cast<ssize_t>(-_lastErrno) : static_cast<ssize_t>(n);
    });
}

size_t KittyMemSys::Write(uintptr_t address, void *buffer, size_t len, MemMode mode)
{
    address = KittyUtils::untagPointer(address);

    return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
        errno = 0;

        iovec local{.iov_base = buf, .iov_len = size};
        iovec remote{.iov_base = reinterpret_cast<void *>(addr), .iov_len = size};

        ssize_t n = KT_EINTR_RETRY(call_process_vm_writev(_pid, &local, 1, &remote, 1, 0));

        if (n < 0)
            _lastErrno = errno;

        return n < 0 ? static_cast<ssize_t>(-_lastErrno) : static_cast<ssize_t>(n);
    });
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

size_t KittyMemIO::Read(uintptr_t address, void *buffer, size_t len, MemMode mode)
{
    address = KittyUtils::untagPointer(address);

    return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
        errno = 0;

        ssize_t n = _pMem->pread(addr, buf, size);

        if (n < 0)
            _lastErrno = _pMem->lastError();

        return n < 0 ? static_cast<ssize_t>(-_lastErrno) : static_cast<ssize_t>(n);
    });
}

size_t KittyMemIO::Write(uintptr_t address, void *buffer, size_t len, MemMode mode)
{
    address = KittyUtils::untagPointer(address);

    return KittyMemoryTransfer(address, buffer, len, mode, [&](uintptr_t addr, void *buf, size_t size) -> ssize_t {
        errno = 0;

        ssize_t n = _pMem->pwrite(addr, buf, size);

        if (n < 0)
            _lastErrno = _pMem->lastError();

        return n < 0 ? static_cast<ssize_t>(-_lastErrno) : static_cast<ssize_t>(n);
    });
}