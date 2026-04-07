#include "KittyTrace.hpp"

bool KittyTraceMgr::attach(int options)
{
    if (_pid <= 0)
        return false;

    if (isAttached())
    {
        _attached = true;
        return true;
    }

    errno = 0;
    if (ptrace(PTRACE_ATTACH, _pid, nullptr, options) == -1L)
    {
        KITTY_LOGE("PTRACE_ATTACH failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    _seized = false;

    int status;
    if (waitpid(_pid, &status, 0) != _pid || !WIFSTOPPED(status))
    {
        KITTY_LOGE("Error occurred while waiting for pid %d to stop. \"%s\".", _pid, strerror(errno));
        ptrace(PTRACE_DETACH, _pid, nullptr, nullptr);
        return false;
    }

    _attached = true;

    if (options != 0)
        setOptions(options);

    return true;
}

bool KittyTraceMgr::seize(int options)
{
    if (_pid <= 0)
        return false;

    if (isAttached())
    {
        _attached = true;
        return true;
    }

    errno = 0;
    if (ptrace(PTRACE_SEIZE, _pid, nullptr, options) == -1L)
    {
        KITTY_LOGE("PTRACE_SEIZE failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    _seized = true;
    _attached = true;

    return true;
}

bool KittyTraceMgr::setOptions(int options)
{
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS, _pid, nullptr, options) == -1L)
    {
        KITTY_LOGE("PTRACE_SETOPTIONS failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    return true;
}

bool KittyTraceMgr::detach()
{
    _attached = false;

    if (!isAttached())
        return true;

    while (true)
    {
        int status = 0;
        if (waitpid(_pid, &status, __WALL | WNOHANG) <= 0)
            break;
    }

    errno = 0;
    if (ptrace(PTRACE_DETACH, _pid, nullptr, nullptr) == -1L)
    {
        KITTY_LOGE("PTRACE_DETACH failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    while (true)
    {
        int status = 0;
        if (waitpid(_pid, &status, __WALL | WNOHANG) <= 0)
            break;
    }

    return true;
}

bool KittyTraceMgr::stop()
{
    if (!_attached || _pid <= 0)
        return false;

    errno = 0;

    if (_seized)
    {
        if (ptrace(PTRACE_INTERRUPT, _pid, nullptr, nullptr) == -1L)
        {
            KITTY_LOGE("PTRACE_INTERRUPT failed for pid %d. \"%s\".", _pid, strerror(errno));
            return false;
        }
    }
    else
    {
        if (tgkill(_pid, _pid, SIGSTOP) == -1)
        {
            KITTY_LOGE("tgkill failed for pid %d. \"%s\".", _pid, strerror(errno));
            return false;
        }
    }

    int status;
    if (waitpid(_pid, &status, 0) != _pid || !WIFSTOPPED(status))
    {
        KITTY_LOGE("Error occurred while waiting for pid %d to stop. \"%s\".", _pid, strerror(errno));
        return false;
    }

    return true;
}

bool KittyTraceMgr::cont(int sig)
{
    if (!_attached || _pid <= 0)
        return false;

    errno = 0;
    if (ptrace(PTRACE_CONT, _pid, nullptr, sig) == -1L)
    {
        KITTY_LOGE("PTRACE_CONT failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    return true;
}

pid_t KittyTraceMgr::wait(int *status, int options, int timeout_ms) const
{
    if (!_attached)
        return -1;

    if (timeout_ms <= 0)
        return waitpid(_pid, status, options);

    int elapsed = 0;
    pid_t res;
    if (!(options & WNOHANG))
        options |= WNOHANG;

    while (elapsed < timeout_ms)
    {
        res = waitpid(_pid, status, options);
        if (res != 0)
            return res;

        usleep(25000);
        elapsed += 25;
    }

    return res;
}

bool KittyTraceMgr::waitSyscall() const
{
    if (!_attached || _pid <= 0)
        return false;

    errno = 0;
    if (ptrace(PTRACE_SYSCALL, _pid, nullptr, nullptr) == -1L)
    {
        KITTY_LOGE("PTRACE_SYSCALL failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    int status = 0;
    waitpid(_pid, &status, 0);
    if (!WIFSTOPPED(status))
        return false;

    return true;
}

bool KittyTraceMgr::step(int steps) const
{
    if (!_attached || _pid <= 0)
        return false;

    int status = 0;
    for (int i = 0; i < steps; ++i)
    {
        errno = 0;
        if (ptrace(PTRACE_SINGLESTEP, _pid, nullptr, nullptr) == -1L)
        {
            KITTY_LOGE("PTRACE_SINGLESTEP failed for pid %d. \"%s\".", _pid, strerror(errno));
            return false;
        }

        if ((i + 1) < steps)
        {
            waitpid(_pid, &status, 0);
            if (!WIFSTOPPED(status))
                return false;
        }
    }

    return true;
}

bool KittyTraceMgr::waitStep(int steps) const
{
    if (!_attached || _pid <= 0)
        return false;

    int status = 0;
    for (int i = 0; i < steps; ++i)
    {
        errno = 0;
        if (ptrace(PTRACE_SINGLESTEP, _pid, nullptr, nullptr) == -1L)
        {
            KITTY_LOGE("PTRACE_SINGLESTEP failed for pid %d. \"%s\".", _pid, strerror(errno));
            return false;
        }

        waitpid(_pid, &status, 0);
        if (!WIFSTOPPED(status))
            return false;
    }

    return true;
}

bool KittyTraceMgr::getRegs(user_regs_struct *regs) const
{
    if (!_attached || _pid <= 0 || !regs)
        return false;

    errno = 0;

#if defined(__LP64__)
    iovec ioVec;
    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    long ret = ptrace(KT_PTRACE_GETREG_REQ, _pid, NT_PRSTATUS, &ioVec);
#else
    long ret = ptrace(KT_PTRACE_GETREG_REQ, _pid, nullptr, regs);
#endif
    if (ret == -1L)
    {
        KITTY_LOGE("PTRACE_GETREGS failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    return true;
}

bool KittyTraceMgr::setRegs(user_regs_struct *regs) const
{
    if (!_attached || _pid <= 0 || !regs)
        return false;

    errno = 0;

#if defined(__LP64__)
    iovec ioVec;
    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    long ret = ptrace(KT_PTRACE_SETREG_REQ, _pid, NT_PRSTATUS, &ioVec);
#else
    long ret = ptrace(KT_PTRACE_SETREG_REQ, _pid, nullptr, regs);
#endif
    if (ret == -1L)
    {
        KITTY_LOGE("PTRACE_SETREGS failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    return true;
}

size_t KittyTraceMgr::peekMem(uintptr_t addr, void *buf, size_t size) const
{
    static constexpr size_t WORD_SIZE = sizeof(long);

    if (!_attached || _pid <= 0)
        return false;

    uint8_t *out = static_cast<uint8_t *>(buf);
    size_t total = 0;

    uintptr_t aligned_start = addr & ~(WORD_SIZE - 1);
    uintptr_t aligned_end = (addr + size + WORD_SIZE - 1) & ~(WORD_SIZE - 1);

    for (uintptr_t cur = aligned_start; cur < aligned_end; cur += WORD_SIZE)
    {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, _pid, (void *)cur, nullptr);
        if (data == -1 && errno)
            return total;

        size_t copy_start = (cur < addr) ? addr - cur : 0;
        size_t copy_end = ((cur + WORD_SIZE) > (addr + size)) ? (addr + size) - cur : WORD_SIZE;
        size_t copy_len = copy_end - copy_start;

        memcpy(out + total, ((uint8_t *)&data) + copy_start, copy_len);
        total += copy_len;
    }

    return total;
}

size_t KittyTraceMgr::pokeMem(uintptr_t addr, const void *buf, size_t size) const
{
    static constexpr size_t WORD_SIZE = sizeof(long);

    if (!_attached || _pid <= 0)
        return false;

    const uint8_t *in = static_cast<const uint8_t *>(buf);
    size_t total = 0;

    uintptr_t aligned_start = addr & ~(WORD_SIZE - 1);
    uintptr_t aligned_end = (addr + size + WORD_SIZE - 1) & ~(WORD_SIZE - 1);

    for (uintptr_t cur = aligned_start; cur < aligned_end; cur += WORD_SIZE)
    {
        size_t write_start = (cur < addr) ? addr - cur : 0;
        size_t write_end = ((cur + WORD_SIZE) > (addr + size)) ? (addr + size) - cur : WORD_SIZE;
        size_t write_len = write_end - write_start;

        long data = 0;

        if (write_len != WORD_SIZE)
        {
            errno = 0;
            data = ptrace(PTRACE_PEEKDATA, _pid, (void *)cur, nullptr);
            if (data == -1 && errno)
                return total;
        }

        memcpy(((uint8_t *)&data) + write_start, in + total, write_len);

        if (ptrace(PTRACE_POKEDATA, _pid, (void *)cur, data) == -1)
            return total;

        total += write_len;
    }

    return total;
}

// refs
// https://github.com/evilsocket/arminject
// https://github.com/Chainfire/injectvm-binderjack
// https://github.com/shunix/TinyInjector
// https://github.com/topjohnwu/Magisk/blob/master/native/src/zygisk/ptrace.cpp

kitty_rp_call_t KittyTraceMgr::_callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, int nargs, ...)
{
    if (!_attached || _pid <= 0 || functionAddress == 0)
        return {KT_RP_CALL_FAILED, {0}};

    user_regs_struct backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));

    // backup current regs
    if (!getRegs(&backup_regs))
    {
        KITTY_LOGE("callFunction(%p): Failed, couldn't get regs.", (void *)functionAddress);
        return {KT_RP_CALL_REGS_FAILED, {0}};
    }

    memcpy(&tmp_regs, &backup_regs, sizeof(backup_regs));

    KT_REGS_ALIGN_STACK(backup_regs);
    KT_REGS_ALIGN_STACK(tmp_regs);
    KT_REGS_ALIGN_STACK(return_regs);

    KITTY_LOGD("callFunction(%p): Calling with %d args.", (void *)functionAddress, nargs);

    std::vector<uintptr_t> vargs(nargs, 0);
    if (nargs > 0)
    {
        va_list vl;
        va_start(vl, nargs);
        for (int i = 0; i < nargs; i++)
        {
            vargs[i] = va_arg(vl, uintptr_t);
        }
        va_end(vl);
    }

    // cleanup failure return
    auto failure_return = [&](KT_RP_CALL_STATUS s = KT_RP_CALL_FAILED) -> kitty_rp_call_t {
        KITTY_LOGE("callFunction(%p): Failed.", (void *)functionAddress);
        if (_autoRestoreRegs)
            setRegs(&backup_regs);
        return {s, {0}};
    };

    auto validate_ret = [this](const user_regs_struct &regs, uintptr_t return_addr) -> bool {
        uintptr_t pc = regs.KT_REG_PC;
        if (pc != return_addr)
        {
#if defined(__arm__)
            if (uintptr_t((intptr_t(pc) & ~1)) != uintptr_t((intptr_t(return_addr) & ~1)))
#elif defined(__i386__) || defined(__x86_64__)
            if (pc < return_addr || pc > (return_addr + 7))
#endif
            {
                siginfo_t si = {};
                getSignalInfo(&si);
                return uintptr_t(si.si_addr) == return_addr;
            }
        }
        return true;
    };

#if defined(__arm__) || defined(__aarch64__)

    // Fill R0-Rx with the first 4 (32-bit) or 8 (64-bit) parameters
    for (int i = 0; (i < nargs) && (i < KT_REG_ARGS_NUM); i++)
    {
#if defined(__arm__)
        tmp_regs.uregs[i] = vargs[i];
#else
        tmp_regs.regs[i] = vargs[i];
#endif
    }

    // push remaining parameters onto stack
    if (nargs > KT_REG_ARGS_NUM)
    {
        KT_REGS_ALIGN_STACK_N(tmp_regs, sizeof(uintptr_t) * (nargs - KT_REG_ARGS_NUM));
        if (!pokeMem(tmp_regs.KT_REG_SP, &vargs[KT_REG_ARGS_NUM], sizeof(uintptr_t) * (nargs - KT_REG_ARGS_NUM)))
            return failure_return(KT_RP_CALL_MEM_FAILED);
    }

    // Set return address
    tmp_regs.KT_REG_LR = callerAddress;

    // Set function address
    tmp_regs.KT_REG_PC = functionAddress;

    // Setup the current processor status register
#if defined(__arm__)
    if (tmp_regs.KT_REG_PC & 1)
    {
        // thumb
        tmp_regs.KT_REG_PC &= (~1u);
        tmp_regs.KT_REG_CPSR |= KT_CPSR_T_MASK;
    }
    else
    {
        // arm
        tmp_regs.KT_REG_CPSR &= ~KT_CPSR_T_MASK;
    }
#endif

#elif defined(__i386__)

    // push all parameters onto stack
    if (nargs > 0)
    {
        KT_REGS_ALIGN_STACK_N(tmp_regs, sizeof(uintptr_t) * nargs);
        if (!pokeMem(tmp_regs.KT_REG_SP, &vargs[0], nargs * sizeof(uintptr_t)))
            return failure_return(KT_RP_CALL_MEM_FAILED);
    }

    // Push return address onto stack
    tmp_regs.KT_REG_SP -= sizeof(uintptr_t);
    if (!pokeMem(tmp_regs.KT_REG_SP, &callerAddress, sizeof(uintptr_t)))
        return failure_return(KT_RP_CALL_MEM_FAILED);

    // Set function address to call
    tmp_regs.KT_REG_IP = functionAddress;

#elif defined(__x86_64__)

    // Fill [RDI, RSI, RDX, RCX, R8, R9] with the first 6 parameters
    for (int i = 0; (i < nargs) && (i < KT_REG_ARGS_NUM); ++i)
    {
        switch (i)
        {
        case 0:
            tmp_regs.rdi = vargs[i];
            break;
        case 1:
            tmp_regs.rsi = vargs[i];
            break;
        case 2:
            tmp_regs.rdx = vargs[i];
            break;
        case 3:
            tmp_regs.rcx = vargs[i];
            break;
        case 4:
            tmp_regs.r8 = vargs[i];
            break;
        case 5:
            tmp_regs.r9 = vargs[i];
            break;
        }
    }

    // Push remaining parameters onto stack
    if (nargs > KT_REG_ARGS_NUM)
    {
        KT_REGS_ALIGN_STACK_N(tmp_regs, sizeof(uintptr_t) * (nargs - KT_REG_ARGS_NUM));
        if (!pokeMem(tmp_regs.KT_REG_SP, &vargs[KT_REG_ARGS_NUM], sizeof(uintptr_t) * (nargs - KT_REG_ARGS_NUM)))
            return failure_return(KT_RP_CALL_MEM_FAILED);
    }

    // Push return address onto stack
    tmp_regs.KT_REG_SP -= sizeof(uintptr_t);
    if (!pokeMem(tmp_regs.KT_REG_SP, &callerAddress, sizeof(uintptr_t)))
        return failure_return(KT_RP_CALL_MEM_FAILED);

    // Set function address to call
    tmp_regs.KT_REG_IP = functionAddress;

    // may be needed
    tmp_regs.rax = 0;
    tmp_regs.orig_rax = 0;

#else
#error "Unsupported ABI"
#endif

    // Set new registers
    if (!setRegs(&tmp_regs))
        return failure_return(KT_RP_CALL_REGS_FAILED);

    // Resume execution
    if (!cont())
        return failure_return(KT_RP_CALL_CONT_FAILED);

    // Catch SIGSEGV caused by our code
    do
    {
        int status = 0;
        errno = 0;
        pid_t wp = wait(&status, WUNTRACED, _remoteCallTimeout);
        if (wp != _pid)
        {
            if (wp == 0)
            {
                stop();
                KITTY_LOGE("callFunction(%p): timedout!", (void *)functionAddress);
                return failure_return(KT_RP_CALL_TIMEOUT);
                ;
            }

            KITTY_LOGE("callFunction(%p): waitpid return %d. \"%s\".", (void *)functionAddress, wp, strerror(errno));
            return failure_return(KT_RP_CALL_WAIT_FAILED);
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("callFunction(%p): Target process exited (%d).", (void *)functionAddress, WEXITSTATUS(status));
            return {KT_RP_CALL_EXITED, {0}};
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("callFunction(%p): Target process terminated (%d).", (void *)functionAddress, WTERMSIG(status));
            return {KT_RP_CALL_EXITED, {0}};
        }

        if (!WIFSTOPPED(status))
            continue;

        if (WSTOPSIG(status) == SIGCHLD || WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP)
        {
            if (!cont())
                return failure_return(KT_RP_CALL_CONT_FAILED);

            continue;
        }

        if (!getRegs(&return_regs))
            return failure_return(KT_RP_CALL_REGS_FAILED);

        KITTY_LOGD("callFunction(%p): Ok.", (void *)functionAddress);

        if (validate_ret(return_regs, callerAddress))
            break;

        KITTY_LOGE("callFunction(%p): Process didn't jump to specified return address (%p)",
                   (void *)functionAddress,
                   (void *)callerAddress);

        KITTY_LOGE("callFunction(%p): PC(%p) | RET(%p).",
                   (void *)functionAddress,
                   (void *)(return_regs.KT_REG_PC),
                   (void *)(return_regs.KT_REG_RET));

        siginfo_t si = {};
        getSignalInfo(&si);

        KITTY_LOGE("callFunction(%p): SIG(%s) | CODE(%d) | ADDR(%p).",
                   (void *)functionAddress,
                   strsignal(si.si_signo),
                   si.si_code,
                   (void *)(si.si_addr));

        auto map = KittyMemoryEx::getAddressMap(_pid, uintptr_t(si.si_addr));
        if (map.isValid())
        {
            KITTY_LOGE("callFunction(%p): Fault Map(<base>+%p) %s",
                       (void *)functionAddress,
                       (void *)((map.offset + uintptr_t(si.si_addr)) - map.startAddress),
                       map.toString().c_str());
        }

        map = KittyMemoryEx::getAddressMap(_pid, return_regs.KT_REG_PC);
        if (map.isValid())
        {
            KITTY_LOGE("callFunction(%p): PC Map(<base>+%p) %s",
                       (void *)functionAddress,
                       (void *)((map.offset + return_regs.KT_REG_PC) - map.startAddress),
                       map.toString().c_str());
        }

        if (!cont(WSTOPSIG(status)))
            return failure_return(KT_RP_CALL_CONT_FAILED);

        return failure_return(KT_RP_CALL_MISMATCH_STOP);
    } while (true);

    kitty_rp_call_t result = {KT_RP_CALL_SUCCESS, {static_cast<intptr_t>(return_regs.KT_REG_RET)}};

    // Restore regs
    if (_autoRestoreRegs)
        setRegs(&backup_regs);

    KITTY_LOGD("callFunction: Calling function %p returned %p.", (void *)functionAddress, (void *)result.result.ptr);

    return result;
}

kitty_rp_call_t KittyTraceMgr::_callSyscall(long sysnr, int nargs, ...)
{
    if (!_attached || _pid <= 0)
        return {KT_RP_CALL_FAILED, {0}};

    user_regs_struct backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));

    // backup current regs
    if (!getRegs(&backup_regs))
    {
        KITTY_LOGE("callSyscall(%d): Failed, couldn't get regs.", int(sysnr));
        return {KT_RP_CALL_REGS_FAILED, {0}};
    }

    memcpy(&tmp_regs, &backup_regs, sizeof(backup_regs));

    KT_REGS_ALIGN_STACK(backup_regs);
    KT_REGS_ALIGN_STACK(tmp_regs);
    KT_REGS_ALIGN_STACK(return_regs);

    std::vector<uintptr_t> vargs(6, 0);
    if (nargs > 0)
    {
        va_list vl;
        va_start(vl, nargs);
        for (int i = 0; i < nargs; i++)
        {
            vargs[i] = va_arg(vl, uintptr_t);
        }
        va_end(vl);
    }

    KITTY_LOGD("callSyscall(%d, 0x%zx, 0x%zx, 0x%zx, 0x%zx, 0x%zx, 0x%zx)",
               int(sysnr),
               vargs[0],
               vargs[1],
               vargs[2],
               vargs[3],
               vargs[4],
               vargs[5]);

    uintptr_t target_pc_mem = tmp_regs.KT_REG_PC;
    std::vector<uint8_t> syscall_code;

#if defined(__arm__)
    bool thumb = (target_pc_mem & 1) != 0 || (tmp_regs.KT_REG_CPSR & KT_CPSR_T_MASK) != 0;
    target_pc_mem &= ~1;
    if (thumb)
        syscall_code.assign(std::begin(KittyTraceInsns::THUMB_SYSCALL), std::end(KittyTraceInsns::THUMB_SYSCALL));
    else
        syscall_code.assign(std::begin(KittyTraceInsns::SYSCALL), std::end(KittyTraceInsns::SYSCALL));
#else
    syscall_code.assign(std::begin(KittyTraceInsns::SYSCALL), std::end(KittyTraceInsns::SYSCALL));
#endif

    std::vector<uint8_t> backup_code(syscall_code.size(), 0);
    if (!peekMem(target_pc_mem, backup_code.data(), backup_code.size()))
    {
        KITTY_LOGE("callSyscall(%d): Failed to backup PC(%p) memory code.", int(sysnr), (void *)target_pc_mem);
        return {KT_RP_CALL_MEM_FAILED, {0}};
    }

    // cleanup failure return
    auto failure_return = [&](KT_RP_CALL_STATUS s = KT_RP_CALL_FAILED) -> kitty_rp_call_t {
        KITTY_LOGE("callSyscall(%d): Failed.", int(sysnr));

        if (_autoRestoreRegs)
            setRegs(&backup_regs);

        pokeMem(target_pc_mem, backup_code.data(), backup_code.size());
        return {s, {0}};
    };

#if defined(__arm__) || defined(__aarch64__)
    for (int i = 0; i < 6; i++)
    {
#if defined(__arm__)
        tmp_regs.uregs[i] = vargs[i];
#else
        tmp_regs.regs[i] = vargs[i];
#endif
    }

#elif defined(__i386__)
    tmp_regs.ebx = vargs[0];
    tmp_regs.ecx = vargs[1];
    tmp_regs.edx = vargs[2];
    tmp_regs.esi = vargs[3];
    tmp_regs.edi = vargs[4];
    tmp_regs.ebp = vargs[5];
    tmp_regs.orig_eax = 0;

#elif defined(__x86_64__)
    tmp_regs.rdi = vargs[0];
    tmp_regs.rsi = vargs[1];
    tmp_regs.rdx = vargs[2];
    tmp_regs.r10 = vargs[3];
    tmp_regs.r8 = vargs[4];
    tmp_regs.r9 = vargs[5];
    tmp_regs.orig_rax = 0;

#endif

    tmp_regs.KT_REG_SYSNR = sysnr;

    if (!pokeMem(target_pc_mem, syscall_code.data(), syscall_code.size()))
    {
        KITTY_LOGE("callSyscall(%d): Failed to write syscall code into PC(%p) memory.",
                   int(sysnr),
                   (void *)target_pc_mem);
        return {KT_RP_CALL_MEM_FAILED, {0}};
    }

    // Set new registers
    if (!setRegs(&tmp_regs))
        return failure_return(KT_RP_CALL_REGS_FAILED);

    // Single step to execute syscall
    if (!step())
        return failure_return(KT_RP_CALL_STEP_FAILED);

    // Wait for step
    do
    {
        errno = 0;
        int status = 0;
        pid_t wp = wait(&status, WUNTRACED);
        if (wp != _pid)
        {
            KITTY_LOGE("callSyscall(%d): waitpid returned %d. \"%s\".", int(sysnr), wp, strerror(errno));
            return failure_return(KT_RP_CALL_WAIT_FAILED);
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("callSyscall(%d): Target process exited (%d).", int(sysnr), WEXITSTATUS(status));
            return {KT_RP_CALL_EXITED, {0}};
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("callSyscall(%d): Target process terminated (%d).", int(sysnr), WTERMSIG(status));
            return {KT_RP_CALL_EXITED, {0}};
        }

        if (!WIFSTOPPED(status))
            continue;

        if (WSTOPSIG(status) == SIGCHLD || WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP)
        {
            if (!cont())
                return failure_return(KT_RP_CALL_CONT_FAILED);

            continue;
        }

        if (!getRegs(&return_regs))
            return failure_return(KT_RP_CALL_REGS_FAILED);

        if (return_regs.KT_REG_PC > tmp_regs.KT_REG_PC && return_regs.KT_REG_PC <= tmp_regs.KT_REG_PC + 16)
            break;

        KITTY_LOGE("callSyscall(%d): Process didn't stop after syscall!", int(sysnr));

        KITTY_LOGE("callSyscall(%d): PC(%p) | RET(%p).",
                   int(sysnr),
                   (void *)(return_regs.KT_REG_PC),
                   (void *)(return_regs.KT_REG_RET));

        siginfo_t si = {};
        getSignalInfo(&si);

        KITTY_LOGE("callSyscall(%d): SIG(%s) | CODE(%d) | ADDR(%p).",
                   int(sysnr),
                   strsignal(si.si_signo),
                   si.si_code,
                   (void *)(si.si_addr));

        auto map = KittyMemoryEx::getAddressMap(_pid, uintptr_t(si.si_addr));
        if (map.isValid())
        {
            KITTY_LOGE("callSyscall(%d): MAP(<base>+%p) %s",
                       int(sysnr),
                       (void *)((map.offset + uintptr_t(si.si_addr)) - map.startAddress),
                       map.toString().c_str());
        }

        if (!cont(WSTOPSIG(status)))
            return failure_return(KT_RP_CALL_CONT_FAILED);

        return failure_return(KT_RP_CALL_MISMATCH_STOP);

    } while (true);

    kitty_rp_call_t result = {KT_RP_CALL_SUCCESS, {static_cast<intptr_t>(return_regs.KT_REG_RET)}};

    if (!pokeMem(target_pc_mem, backup_code.data(), backup_code.size()))
    {
        KITTY_LOGW("callSyscall(%d): Failed to restore PC(%p) memory code!", int(sysnr), (void *)target_pc_mem);
    }

    // Restore regs
    if (_autoRestoreRegs)
        setRegs(&backup_regs);

    KITTY_LOGD("callSyscall(%d): returned %p.", int(sysnr), (void *)result.result.ptr);
    return result;
}

KT_BP_RESULT KittyTraceMgr::setSoftBreakpointAndWait(uintptr_t address,
                                                     const std::function<bool(user_regs_struct regs)> &cb,
                                                     int timeout_ms)
{
    if (!_attached || _pid <= 0 || address == 0)
        return KT_BP_FAILED;

#if defined(__arm__)
    bool thumb = address & 1;
    if (thumb)
        address &= ~1;
    else
        address &= ~3UL;
#elif defined(__aarch64__)
    address &= ~3UL;
#endif

    pid_t tid = _pid;

    std::vector<uint8_t> brk_code(sizeof(uintptr_t), 0);
    std::vector<uint8_t> bak_code(sizeof(uintptr_t), 0);
    int status = 0;
    pid_t wp = 0;
    user_regs_struct regs = {};

    // cleanup failure return
    auto failure_return = [&](KT_BP_RESULT res = KT_BP_FAILED) -> KT_BP_RESULT {
        KITTY_LOGE("setSoftBreakpointAndWait(%p): Failed.", (void *)address);
        pokeMem(address, bak_code.data(), bak_code.size());
        return res;
    };

    auto validate_trap = [this](const user_regs_struct &regs, uintptr_t trap_addr) -> bool {
        uintptr_t pc = regs.KT_REG_PC;
        uintptr_t max_range = KT_ALIGN_UP(trap_addr + sizeof(KittyTraceInsns::BRKP), sizeof(uintptr_t));
        if (!(pc >= trap_addr && pc <= max_range))
        {
            siginfo_t si = {};
            getSignalInfo(&si);
            return uintptr_t(si.si_addr) >= trap_addr && uintptr_t(si.si_addr) <= max_range;
        }
        return true;
    };

again:
    wp = 0;
    status = 0;
    memset(&regs, 0, sizeof(regs));

    if (!peekMem(address, bak_code.data(), bak_code.size()))
    {
        KITTY_LOGE("setSoftBreakpointAndWait(%p): Failed to backup memory code.", (void *)address);
        return KT_BP_MEM_FAILED;
    }

#if defined(__arm__)
    if (thumb)
        memcpy(brk_code.data(), KittyTraceInsns::THUMB_BRKP, sizeof(KittyTraceInsns::THUMB_BRKP));
    else
        memcpy(brk_code.data(), KittyTraceInsns::BRKP, sizeof(KittyTraceInsns::BRKP));
#else
    memcpy(brk_code.data(), KittyTraceInsns::BRKP, sizeof(KittyTraceInsns::BRKP));
#endif

    if (!pokeMem(address, brk_code.data(), brk_code.size()))
    {
        KITTY_LOGE("setSoftBreakpointAndWait(%p): Failed to write brk code into memory.", (void *)address);
        return KT_BP_MEM_FAILED;
    }

    if (!cont())
        return failure_return(KT_BP_CONT_FAILED);

    do
    {
        errno = 0;
        status = 0;
        wp = wait(&status, WUNTRACED, timeout_ms);
        if (wp != tid)
        {
            if (wp == 0)
            {
                stop();
                KITTY_LOGE("setSoftBreakpointAndWait(%p): timedout!", (void *)address);
                pokeMem(address, bak_code.data(), bak_code.size());
                return KT_BP_TIMEOUT;
            }

            KITTY_LOGE("setSoftBreakpointAndWait(%p): waitpid returned %d. \"%s\".",
                       (void *)address,
                       wp,
                       strerror(errno));

            return failure_return(KT_BP_WAIT_FAILED);
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("setSoftBreakpointAndWait(%p): Target process exited (%d).",
                       (void *)address,
                       WEXITSTATUS(status));
            return KT_BP_EXITED;
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("setSoftBreakpointAndWait(%p): Target process terminated (%d).",
                       (void *)address,
                       WTERMSIG(status));
            return KT_BP_EXITED;
        }

        if (!WIFSTOPPED(status))
            continue;

        if (WSTOPSIG(status) == SIGCHLD || WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP)
        {
            if (!cont())
                return failure_return(KT_BP_CONT_FAILED);

            continue;
        }

        if (!getRegs(&regs))
            return failure_return(KT_BP_REGS_FAILED);

        if (WSTOPSIG(status) == SIGTRAP)
        {
            if (validate_trap(regs, address))
                break;

            KITTY_LOGE("setSoftBreakpointAndWait(%p): Process didn't stop at specified Hardware Breakpoint",
                       (void *)address);
        }
        else
        {
            KITTY_LOGE("setSoftBreakpointAndWait(%p): Target process didn't stop with SIGTRAP", (void *)address);
        }

        KITTY_LOGE("setSoftBreakpointAndWait(%p): PC(%p) | RET(%p).",
                   (void *)address,
                   (void *)(regs.KT_REG_PC),
                   (void *)(regs.KT_REG_RET));

        siginfo_t si = {};
        getSignalInfo(&si);

        KITTY_LOGE("setSoftBreakpointAndWait(%p): SIG(%s) | CODE(%d) | ADDR(%p).",
                   (void *)address,
                   strsignal(si.si_signo),
                   si.si_code,
                   (void *)(si.si_addr));

        auto map = KittyMemoryEx::getAddressMap(_pid, uintptr_t(si.si_addr));
        if (map.isValid())
        {
            KITTY_LOGE("setSoftBreakpointAndWait(%p): MAP(<base>+%p) %s",
                       (void *)address,
                       (void *)((map.offset + uintptr_t(si.si_addr)) - map.startAddress),
                       map.toString().c_str());
        }

        if (!cont(WSTOPSIG(status)))
            return failure_return(KT_BP_CONT_FAILED);

        return failure_return(KT_BP_MISMATCH_STOP);

    } while (true);

    if (!pokeMem(address, bak_code.data(), bak_code.size()))
    {
        KITTY_LOGE("setSoftBreakpointAndWait(%p): Failed to restore memory code!", (void *)address);
        return KT_BP_MEM_FAILED;
    }

#if defined(__i386__) || defined(__x86_64__)
    regs.KT_REG_PC -= sizeof(KittyTraceInsns::BRKP);
    if (!setRegs(&regs))
    {
        KITTY_LOGE("setSoftBreakpointAndWait(%p): Failed to rewind PC!", (void *)address);
        return KT_BP_REGS_FAILED;
    }
#endif

    KITTY_LOGD("setSoftBreakpointAndWait(%p): Success PC(%p).", (void *)address, (void *)regs.KT_REG_PC);

    if (cb && !cb(regs))
    {
        if (!waitStep())
        {
            KITTY_LOGE("setSoftBreakpointAndWait(%p): Failed to step past breakpoint!", (void *)address);
            return KT_BP_STEP_FAILED;
        }

        goto again;
    }

    return KT_BP_SUCCESS;
}

KT_BP_RESULT KittyTraceMgr::setHardBreakpointAndWait(uintptr_t address,
                                                     KT_HW_BP_TYPE type,
                                                     KT_HW_BP_SIZE size,
                                                     int slot,
                                                     const std::function<bool(user_regs_struct regs)> &cb,
                                                     int timeout_ms)
{
    if (!_attached || _pid <= 0 || address == 0)
        return KT_BP_FAILED;

    pid_t tid = _pid;
    int status = 0;
    pid_t wp = 0;
    user_regs_struct regs = {};

    auto failure_return = [&](KT_BP_RESULT res = KT_BP_FAILED) -> KT_BP_RESULT {
        KITTY_LOGE("setHardBreakpointAndWait(%p): Failed.", (void *)address);
        clearHwBreakpoint(type, slot);
        return res;
    };

    auto validate_trap = [this, size](const user_regs_struct &regs, uintptr_t trap_addr) -> bool {
        trap_addr &= ~1;
        trap_addr &= ~(sizeof(uintptr_t) - 1);
        uintptr_t pc = regs.KT_REG_PC;
        uintptr_t max_range = KT_ALIGN_UP(trap_addr + std::max(int(size), int(sizeof(KittyTraceInsns::BRKP))),
                                          int(sizeof(uintptr_t)));
        if (!(pc >= trap_addr && pc <= max_range))
        {
            siginfo_t si = {};
            getSignalInfo(&si);
            return uintptr_t(si.si_addr) >= trap_addr && uintptr_t(si.si_addr) <= max_range;
        }
        return true;
    };

again:

    if (type == KT_HW_BP_EXECUTE)
    {
#if defined(__arm__)
        if (!setHwBreakpoint(address, type, (address & 1) != 0 ? KT_HW_BP_SIZE_2 : KT_HW_BP_SIZE_4, slot))
#elif defined(__aarch64__)
        if (!setHwBreakpoint(address, type, KT_HW_BP_SIZE_4, slot))
#else
        if (!setHwBreakpoint(address, type, KT_HW_BP_SIZE_1, slot))
#endif
        {
            KITTY_LOGE("setHardBreakpointAndWait(%p): Failed to set breakpoint. \"%s\"",
                       (void *)address,
                       strerror(errno));
            return KT_BP_FAILED;
        }
    }
    else
    {
        if (!setHwBreakpoint(address, type, size, slot))
        {
            KITTY_LOGE("setHardBreakpointAndWait(%p): Failed to set watchpoint. \"%s\"",
                       (void *)address,
                       strerror(errno));
            return KT_BP_FAILED;
        }
    }

    if (!cont())
        return failure_return(KT_BP_CONT_FAILED);

    do
    {
        errno = 0;
        status = 0;
        wp = wait(&status, WUNTRACED, timeout_ms);
        if (wp != tid)
        {
            if (wp == 0)
            {
                stop();
                KITTY_LOGE("setHardBreakpointAndWait(%p): timedout!", (void *)address);
                clearHwBreakpoint(type, slot);
                return KT_BP_TIMEOUT;
            }

            KITTY_LOGE("setHardBreakpointAndWait(%p): waitpid returned %d. \"%s\".",
                       (void *)address,
                       wp,
                       strerror(errno));

            return failure_return(KT_BP_WAIT_FAILED);
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("setHardBreakpointAndWait(%p): Target process exited (%d).",
                       (void *)address,
                       WEXITSTATUS(status));
            return KT_BP_EXITED;
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("setHardBreakpointAndWait(%p): Target process terminated (%d).",
                       (void *)address,
                       WTERMSIG(status));
            return KT_BP_EXITED;
        }

        if (!WIFSTOPPED(status))
            continue;

        if (WSTOPSIG(status) == SIGCHLD || WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP)
        {
            if (!cont())
                return failure_return(KT_BP_CONT_FAILED);

            continue;
        }

        if (!getRegs(&regs))
            return failure_return(KT_BP_REGS_FAILED);

        if (WSTOPSIG(status) == SIGTRAP)
        {
            /*siginfo_t si{};
            getSignalInfo(&si);
            if (si.si_code == 4)
                break;*/

            if (validate_trap(regs, address))
                break;

            KITTY_LOGE("setHardBreakpointAndWait(%p): Process didn't stop at specified Hardware Breakpoint",
                       (void *)address);
        }
        else
        {
            KITTY_LOGE("setHardBreakpointAndWait(%p): Target process didn't stop with SIGTRAP", (void *)address);
        }

        KITTY_LOGE("setHardBreakpointAndWait(%p): PC(%p) | RET(%p).",
                   (void *)address,
                   (void *)(regs.KT_REG_PC),
                   (void *)(regs.KT_REG_RET));

        siginfo_t si = {};
        getSignalInfo(&si);

        KITTY_LOGE("setHardBreakpointAndWait(%p): SIG(%s) | CODE(%d) | ADDR(%p).",
                   (void *)address,
                   strsignal(si.si_signo),
                   si.si_code,
                   (void *)(si.si_addr));

        auto map = KittyMemoryEx::getAddressMap(_pid, uintptr_t(si.si_addr));
        if (map.isValid())
        {
            KITTY_LOGE("setHardBreakpointAndWait(%p): MAP(<base>+%p) %s",
                       (void *)address,
                       (void *)((map.offset + uintptr_t(si.si_addr)) - map.startAddress),
                       map.toString().c_str());
        }

        if (!cont(WSTOPSIG(status)))
            return failure_return(KT_BP_CONT_FAILED);

        // return failure_return(KT_BP_MISMATCH_STOP);

    } while (true);

    KITTY_LOGD("setHardBreakpointAndWait(%p): Success PC(%p).", (void *)address, (void *)regs.KT_REG_PC);

    clearHwBreakpoint(type, slot);

    if (cb && !cb(regs))
    {
        if (!waitStep())
        {
            KITTY_LOGE("setHardBreakpointAndWait(%p): Failed to step past breakpoint!", (void *)address);
            return KT_BP_STEP_FAILED;
        }

        goto again;
    }

    return KT_BP_SUCCESS;
}

#if defined(__arm__) && !defined(PTRACE_GETHBPREGS)
#define PTRACE_GETHBPREGS 29
#define PTRACE_SETHBPREGS 30
#endif

bool KittyTraceMgr::setHwBreakpoint(uintptr_t address, KT_HW_BP_TYPE type, KT_HW_BP_SIZE size, int slot)
{
    errno = 0;
    pid_t tid = _pid;

#if defined(__arm__) || defined(__aarch64__)
    address &= ~1;
    size_t alignment_mask = type == KT_HW_BP_EXECUTE ? (sizeof(uint32_t) - 1) : (sizeof(uintptr_t) - 1);

    uintptr_t offset = address & alignment_mask;
    address &= ~alignment_mask;

    // Build the Byte Address Select (BAS) mask based on size and offset
    uint32_t bas = ((1U << size) - 1) << offset;

    uint32_t type_bits = 0;
    switch (type)
    {
    case KT_HW_BP_EXECUTE:
        type_bits = 0;
        break;
    case KT_HW_BP_READ:
        type_bits = 1;
        break;
    case KT_HW_BP_WRITE:
        type_bits = 2;
        break;
    case KT_HW_BP_ACCESS:
        type_bits = 3;
        break;
    }

    uint32_t privilege = (1 << 1); // User mode only
    uint32_t enabled = 1;          // Bit 0: Enable
    uint32_t ctrl = enabled | privilege | (type_bits << 3) | (bas << 5);

#if defined(__arm__)
    long vr_idx = type == KT_HW_BP_EXECUTE ? (((slot * 2) + 1)) : (-(slot * 2) + 1);
    long cr_idx = type == KT_HW_BP_EXECUTE ? (((slot * 2) + 2)) : (-(slot * 2) + 2);
    return ptrace(PTRACE_SETHBPREGS, tid, vr_idx, &address) != -1L &&
           ptrace(PTRACE_SETHBPREGS, tid, cr_idx, &ctrl) != -1L;

#elif defined(__aarch64__)
    struct user_hwdebug_state state{};

    struct iovec iov;
    iov.iov_base = &state;
    iov.iov_len = offsetof(struct user_hwdebug_state, dbg_regs) + (sizeof(state.dbg_regs[0]) * (slot + 1));

    int regset = (type == KT_HW_BP_EXECUTE) ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH;

    // Read current state
    if (ptrace(PTRACE_GETREGSET, tid, regset, &iov) == -1)
        return false;

    // Overwrite slot
    state.dbg_regs[slot].addr = address;
    state.dbg_regs[slot].ctrl = ctrl;

    // Update state
    return ptrace(PTRACE_SETREGSET, tid, regset, &iov) != -1L;
#endif

#elif defined(__x86_64__) || defined(__i386__)
    // Set Address in DR0-DR3
    if (ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg) + slot * sizeof(((struct user*)0)->u_debugreg[0]), address) == -1L)
        return false;

    // Retrieve current DR7 to avoid overwriting other slots
    errno = 0;
    unsigned long dr7 = ptrace(PTRACE_PEEKUSER, tid, offsetof(struct user, u_debugreg[7]), 0);
    if (dr7 == ((unsigned long)-1) && errno != 0)
        return false;

    // Configure type bits
    unsigned long type_bits = 0;
    switch (type)
    {
    case KT_HW_BP_EXECUTE:
        type_bits = 0;
        break;
    case KT_HW_BP_WRITE:
        type_bits = 1;
        break;
    case KT_HW_BP_READ:
    case KT_HW_BP_ACCESS:
        type_bits = 3;
        break; // x86 doesn't support 'Read-Only'
    }

    // Configure length
    unsigned long len_bits = 0;
    if (type != KT_HW_BP_EXECUTE)
    {
        if (address % size != 0)
            return false;

        switch (size)
        {
        case 1:
            len_bits = 0;
            break;
        case 2:
            len_bits = 1;
            break;
        case 4:
            len_bits = 3;
            break;
        case 8:
            len_bits = 2;
            break; // x64 only
        default:
            return false;
        }
    }

    int l_bit = (slot * 2);        // Local Enable bits are 0, 2, 4, 6
    int rw_bit = 16 + (slot * 4);  // RW bits are 16, 20, 24, 28
    int len_bit = 18 + (slot * 4); // LEN bits are 18, 22, 26, 30

    dr7 &= ~((3UL << rw_bit) | (3UL << len_bit) | (1UL << l_bit));         // Clear slot
    dr7 |= (type_bits << rw_bit) | (len_bits << len_bit) | (1UL << l_bit); // Set slot

    // Update DR7
    return ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[7]), dr7) != -1L;
#endif
}

bool KittyTraceMgr::clearHwBreakpoint(KT_HW_BP_TYPE type, int slot)
{
    pid_t tid = _pid;
    errno = 0;
    ((void)type);

#if defined(__arm__)
    uintptr_t address = 0;
    uint32_t ctrl = 0;
    long vr_idx = type == KT_HW_BP_EXECUTE ? (((slot * 2) + 1)) : (-(slot * 2) + 1);
    long cr_idx = type == KT_HW_BP_EXECUTE ? (((slot * 2) + 2)) : (-(slot * 2) + 2);
    return ptrace(PTRACE_SETHBPREGS, tid, vr_idx, &address) != -1L &&
           ptrace(PTRACE_SETHBPREGS, tid, cr_idx, &ctrl) != -1L;

#elif defined(__aarch64__)
    struct user_hwdebug_state state{};

    struct iovec iov;
    iov.iov_base = &state;
    iov.iov_len = offsetof(struct user_hwdebug_state, dbg_regs) + (sizeof(state.dbg_regs[0]) * (slot + 1));

    int regset = (type == KT_HW_BP_EXECUTE) ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH;

    // Read current state
    if (ptrace(PTRACE_GETREGSET, tid, regset, &iov) == -1)
        return false;

    // Overwrite slot
    state.dbg_regs[slot].addr = 0;
    state.dbg_regs[slot].ctrl = 0;

    // Update state
    return ptrace(PTRACE_SETREGSET, tid, regset, &iov) != -1L;

#elif defined(__x86_64__) || defined(__i386__)
    errno = 0;
    unsigned long dr7 = ptrace(PTRACE_PEEKUSER, tid, offsetof(struct user, u_debugreg[7]), 0);
    if (dr7 == ((unsigned long)-1) && errno != 0)
        return false;

    // Clear L/G enable bits (bits 0-7)
    dr7 &= ~(3UL << (slot * 2));

    // Clear RW/LEN bits (bits 16-31)
    // Each slot has 4 bits of config starting at bit 16
    dr7 &= ~(0xFUL << (16 + (slot * 4)));

    if (ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[7]), dr7) == -1L)
        return false;

    if (ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg) + slot * sizeof(((struct user*)0)->u_debugreg[0]), 0) == -1L)
        return false;

    ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[6]), 0);

    return true;
#endif
}
