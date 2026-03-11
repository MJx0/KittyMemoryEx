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

    errno = 0;
    if (ptrace(PTRACE_DETACH, _pid, nullptr, nullptr) == -1L)
    {
        KITTY_LOGE("PTRACE_DETACH failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
    }

    return true;
}

bool KittyTraceMgr::interrupt()
{
    if (!_attached || _pid <= 0)
        return false;

    errno = 0;
    if (ptrace(PTRACE_INTERRUPT, _pid, nullptr, nullptr) == -1L)
    {
        KITTY_LOGE("PTRACE_INTERRUPT failed for pid %d. \"%s\".", _pid, strerror(errno));
        return false;
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

bool KittyTraceMgr::peekMem(uintptr_t addr, void *buf, size_t size) const
{
    if (!_attached || _pid <= 0)
        return false;

    long len = size / sizeof(long);
    long nremain = size % sizeof(long);
    uint8_t *cursrc = (uint8_t *)addr;
    uint8_t *curdst = (uint8_t *)buf;

    for (long i = 0; i < len; i++)
    {
        long rbuf = ptrace(PTRACE_PEEKTEXT, _pid, cursrc, nullptr);
        if (rbuf == -1)
            return false;

        memcpy(curdst, (void *)(&rbuf), sizeof(long));
        cursrc += sizeof(long);
        curdst += sizeof(long);
    }

    if (nremain > 0)
    {
        long rbuf = ptrace(PTRACE_PEEKTEXT, _pid, cursrc, nullptr);
        if (rbuf == -1)
            return false;

        memcpy(curdst, (char *)(&rbuf), nremain);
    }

    return true;
}

bool KittyTraceMgr::pokeMem(uintptr_t addr, const void *buf, size_t size) const
{
    if (!_attached || _pid <= 0)
        return false;

    long count = size / sizeof(long);
    long remain = size % sizeof(long);
    const uint8_t *cursrc = (const uint8_t *)buf;
    uint8_t *curdst = (uint8_t *)addr;

    for (long i = 0; i < count; i++)
    {
        long rbuf = 0;
        memcpy((void *)(&rbuf), cursrc, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, _pid, curdst, rbuf) == -1)
            return false;

        cursrc += sizeof(long);
        curdst += sizeof(long);
    }

    if (remain > 0)
    {
        long rbuf = ptrace(PTRACE_PEEKTEXT, _pid, curdst, nullptr);
        if (rbuf == -1)
            return false;

        memcpy((void *)(&rbuf), cursrc, remain);
        return ptrace(PTRACE_POKETEXT, _pid, curdst, rbuf) != -1;
    }

    return true;
}

// refs
// https://github.com/evilsocket/arminject
// https://github.com/Chainfire/injectvm-binderjack
// https://github.com/shunix/TinyInjector
// https://github.com/topjohnwu/Magisk/blob/master/native/src/zygisk/ptrace.cpp

uintptr_t KittyTraceMgr::_callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, int nargs, ...)
{
    if (!_attached || _pid <= 0 || functionAddress == 0)
        return 0;

    user_regs_struct backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));

    // backup current regs
    if (!getRegs(&backup_regs))
    {
        KITTY_LOGE("callFunction(%p): Failed, couldn't get regs.", (void *)functionAddress);
        return 0;
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
    auto failure_return = [&]() -> uintptr_t {
        KITTY_LOGE("callFunction(%p): Failed.", (void *)functionAddress);
        if (_autoRestoreRegs)
            setRegs(&backup_regs);
        return 0;
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
            return failure_return();
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
            return failure_return();
    }

    // Push return address onto stack
    tmp_regs.KT_REG_SP -= sizeof(uintptr_t);
    if (!pokeMem(tmp_regs.KT_REG_SP, &callerAddress, sizeof(uintptr_t)))
        return failure_return();

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
            return failure_return();
    }

    // Push return address onto stack
    tmp_regs.KT_REG_SP -= sizeof(uintptr_t);
    if (!pokeMem(tmp_regs.KT_REG_SP, &callerAddress, sizeof(uintptr_t)))
        return failure_return();

    // Set function address to call
    tmp_regs.KT_REG_IP = functionAddress;

    // may be needed
    tmp_regs.rax = 0;
    tmp_regs.orig_rax = 0;

#else
#error "Unsupported ABI"
#endif

    // Set new registers and resume execution
    if (!setRegs(&tmp_regs) || !cont())
        return failure_return();

    // Catch SIGSEGV caused by our code
    do
    {
        int status = 0;
        errno = 0;
        pid_t wp = wait(&status, WUNTRACED);
        if (wp != _pid)
        {
            KITTY_LOGE("callFunction(%p): waitpid return %d. \"%s\".", (void *)functionAddress, wp, strerror(errno));
            return failure_return();
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("callFunction(%p): Target process exited (%d).", (void *)functionAddress, WEXITSTATUS(status));
            return 0;
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("callFunction(%p): Target process terminated (%d).", (void *)functionAddress, WTERMSIG(status));
            return 0;
        }

        if (!WIFSTOPPED(status))
        {
            KITTY_LOGE("callFunction(%p): Target process didn't stop (status(0x%x)).",
                       (void *)functionAddress,
                       (status));
            return failure_return();
        }

        if (WSTOPSIG(status) == SIGSTOP)
        {
            KITTY_LOGD("callFunction(%p): Cont...", (void *)functionAddress);

            if (!cont())
                return failure_return();

            continue;
        }

        if (!getRegs(&return_regs))
            return failure_return();

        KITTY_LOGD("callFunction(%p): Ok.", (void *)functionAddress);

        if (!validate_ret(return_regs, callerAddress))
        {
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
                KITTY_LOGE("callFunction(%p): MAP(<base>+%p) %s",
                           (void *)functionAddress,
                           (void *)((map.offset + uintptr_t(si.si_addr)) - map.startAddress),
                           map.toString().c_str());
            }

            return failure_return();
        }

        break;

    } while (true);

    uintptr_t result = return_regs.KT_REG_RET;

    // Restore regs
    if (_autoRestoreRegs)
        setRegs(&backup_regs);

    KITTY_LOGD("callFunction: Calling function %p returned %p.", (void *)functionAddress, (void *)result);

    return result;
}

intptr_t KittyTraceMgr::_callSyscall(long sysnr, int nargs, ...)
{
    if (!_attached || _pid <= 0)
        return 0;

    user_regs_struct backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));

    // backup current regs
    if (!getRegs(&backup_regs))
    {
        KITTY_LOGE("callSyscall(%d): Failed, couldn't get regs.", int(sysnr));
        return 0;
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

#if defined(__arm__)
    tmp_regs.KT_REG_PC &= ~1u;
#endif

    uintptr_t target_pc_mem = tmp_regs.KT_REG_PC;

    std::vector<uint8_t> syscall_brk_code(std::begin(KittyTraceInsns::syscallInsn),
                                          std::end(KittyTraceInsns::syscallInsn));
    {
        syscall_brk_code.insert(syscall_brk_code.end(),
                                std::begin(KittyTraceInsns::brkTrapInsn),
                                std::end(KittyTraceInsns::brkTrapInsn));
        int remain = (int(sizeof(long)) - int(syscall_brk_code.size()));
        if (remain > 0)
        {
            for (int i = 0; i < (remain / int(sizeof(KittyTraceInsns::nopInsn))); i++)
                syscall_brk_code.insert(syscall_brk_code.end(),
                                        std::begin(KittyTraceInsns::nopInsn),
                                        std::end(KittyTraceInsns::nopInsn));
        }
    }

    std::vector<uint8_t> backup_code(syscall_brk_code.size(), 0);
    if (!peekMem(target_pc_mem, backup_code.data(), backup_code.size()))
    {
        KITTY_LOGE("callSyscall(%d): Failed to backup PC(%p) memory code.", int(sysnr), (void *)target_pc_mem);
        return 0;
    }

    // cleanup failure return
    auto failure_return = [&]() -> uintptr_t {
        KITTY_LOGE("callSyscall(%d): Failed.", int(sysnr));

        if (_autoRestoreRegs)
            setRegs(&backup_regs);

        pokeMem(target_pc_mem, backup_code.data(), backup_code.size());
        return 0;
    };

    auto validate_trap = [this](const user_regs_struct &regs, uintptr_t trap_addr) -> bool {
        uintptr_t pc = regs.KT_REG_PC;
        if (pc != trap_addr && pc != (trap_addr + sizeof(KittyTraceInsns::brkTrapInsn)))
        {
            siginfo_t si = {};
            getSignalInfo(&si);
            return uintptr_t(si.si_addr) == trap_addr;
        }
        return true;
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

    if (!pokeMem(target_pc_mem, syscall_brk_code.data(), syscall_brk_code.size()))
    {
        KITTY_LOGE("callSyscall(%d): Failed to write syscall code into PC(%p) memory.",
                   int(sysnr),
                   (void *)target_pc_mem);
        return 0;
    }

    // Set new registers and resume execution
    if (!setRegs(&tmp_regs) || !cont())
        return failure_return();

    // Catch SIGTRAP caused by our code
    do
    {
        errno = 0;
        int status = 0;
        pid_t wp = wait(&status, WUNTRACED);
        if (wp != _pid)
        {
            KITTY_LOGE("callSyscall(%d): waitpid returned %d. \"%s\".", int(sysnr), wp, strerror(errno));
            return failure_return();
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("callSyscall(%d): Target process exited (%d).", int(sysnr), WEXITSTATUS(status));
            return 0;
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("callSyscall(%d): Target process terminated (%d).", int(sysnr), WTERMSIG(status));
            return 0;
        }

        if (!WIFSTOPPED(status))
        {
            KITTY_LOGE("callSyscall(%d): Target process didn't stop (status(0x%X)).", int(sysnr), (status));
            return failure_return();
        }

        if (WSTOPSIG(status) == SIGSTOP)
        {
            if (!cont())
                return failure_return();

            continue;
        }

        if (!getRegs(&return_regs))
            return failure_return();

        if (WSTOPSIG(status) == SIGTRAP)
        {
            uintptr_t trap_addr = tmp_regs.KT_REG_PC + sizeof(KittyTraceInsns::syscallInsn);
            if (validate_trap(return_regs, trap_addr))
                break;

            KITTY_LOGE("callSyscall(%d): Process didn't stop at specified brkp (%p)", int(sysnr), (void *)trap_addr);
        }
        else
        {
            KITTY_LOGE("callSyscall(%d): Target process didn't stop with SIGTRAP", int(sysnr));
        }

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

        return failure_return();

    } while (true);

    uintptr_t result = return_regs.KT_REG_RET;

    if (!pokeMem(target_pc_mem, backup_code.data(), backup_code.size()))
    {
        KITTY_LOGW("callSyscall(%d): Failed to restore PC(%p) memory code!", int(sysnr), (void *)target_pc_mem);
    }

    // Restore regs
    if (_autoRestoreRegs)
        setRegs(&backup_regs);

    KITTY_LOGD("callSyscall(%d): returned %p.", int(sysnr), (void *)result);
    return result;
}

bool KittyTraceMgr::softTrapWait(uintptr_t address, const std::function<bool(user_regs_struct regs)> &cb)
{
    if (!_attached || _pid <= 0 || address == 0)
        return 0;

#if defined(__arm__) || defined(__aarch64__)
    address &= ~3;
#endif

    pid_t tid = _pid;

    std::vector<uint8_t> brk_code(sizeof(uintptr_t), 0);
    std::vector<uint8_t> bak_code(sizeof(uintptr_t), 0);
    int status = 0;
    pid_t wp = 0;
    user_regs_struct regs = {};

    // cleanup failure return
    auto failure_return = [&]() -> bool {
        KITTY_LOGE("softTrapWait(%p): Failed.", (void *)address);

        pokeMem(address, bak_code.data(), bak_code.size());
        return false;
    };

    auto validate_trap = [this](const user_regs_struct &regs, uintptr_t trap_addr) -> bool {
        uintptr_t pc = regs.KT_REG_PC;
        if (pc != trap_addr && pc != (trap_addr + sizeof(KittyTraceInsns::brkTrapInsn)))
        {
            siginfo_t si = {};
            getSignalInfo(&si);
            return uintptr_t(si.si_addr) == trap_addr;
        }
        return true;
    };

again:
    wp = 0;
    status = 0;
    memset(&regs, 0, sizeof(regs));

    if (!peekMem(address, bak_code.data(), bak_code.size()))
    {
        KITTY_LOGE("softTrapWait(%p): Failed to backup memory code.", (void *)address);
        return false;
    }

    for (int i = 0; i < (int(sizeof(uint32_t)) / int(sizeof(KittyTraceInsns::nopInsn))); i++)
    {
        memcpy(brk_code.data() + (i * sizeof(KittyTraceInsns::nopInsn)),
               KittyTraceInsns::nopInsn,
               sizeof(KittyTraceInsns::nopInsn));
    }
    memcpy(brk_code.data(), KittyTraceInsns::brkTrapInsn, sizeof(KittyTraceInsns::brkTrapInsn));

    if (!pokeMem(address, brk_code.data(), brk_code.size()))
    {
        KITTY_LOGE("softTrapWait(%p): Failed to write brk code into memory.", (void *)address);
        return false;
    }

    // resume execution
    if (!cont())
        return failure_return();

    // Catch SIGTRAP
    do
    {
        errno = 0;
        status = 0;
        wp = wait(&status, WUNTRACED);
        if (wp != tid)
        {
            KITTY_LOGE("softTrapWait(%p): waitpid returned %d. \"%s\".", (void *)address, wp, strerror(errno));
            return failure_return();
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("softTrapWait(%p): Target process exited (%d).", (void *)address, WEXITSTATUS(status));
            return false;
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("softTrapWait(%p): Target process terminated (%d).", (void *)address, WTERMSIG(status));
            return false;
        }

        if (!WIFSTOPPED(status))
        {
            KITTY_LOGE("softTrapWait(%p): Target process didn't stop (status(0x%X)).", (void *)address, (status));
            return failure_return();
        }

        if (WSTOPSIG(status) == SIGSTOP)
        {
            if (!cont())
                return failure_return();

            continue;
        }

        if (!getRegs(&regs))
            return failure_return();

        if (WSTOPSIG(status) == SIGTRAP)
        {
            if (validate_trap(regs, address))
                break;

            KITTY_LOGE("softTrapWait(%p): Process didn't stop at specified brkp", (void *)address);
        }
        else
        {
            KITTY_LOGE("softTrapWait(%p): Target process didn't stop with SIGTRAP", (void *)address);
        }

        KITTY_LOGE("softTrapWait(%p): PC(%p) | RET(%p).",
                   (void *)address,
                   (void *)(regs.KT_REG_PC),
                   (void *)(regs.KT_REG_RET));

        siginfo_t si = {};
        getSignalInfo(&si);

        KITTY_LOGE("softTrapWait(%p): SIG(%s) | CODE(%d) | ADDR(%p).",
                   (void *)address,
                   strsignal(si.si_signo),
                   si.si_code,
                   (void *)(si.si_addr));

        auto map = KittyMemoryEx::getAddressMap(_pid, uintptr_t(si.si_addr));
        if (map.isValid())
        {
            KITTY_LOGE("softTrapWait(%p): MAP(<base>+%p) %s",
                       (void *)address,
                       (void *)((map.offset + uintptr_t(si.si_addr)) - map.startAddress),
                       map.toString().c_str());
        }

        return failure_return();
    } while (true);

    if (!pokeMem(address, bak_code.data(), bak_code.size()))
    {
        KITTY_LOGE("softTrapWait(%p): Failed to restore memory code!", (void *)address);
        return false;
    }

#if defined(__i386__) || defined(__x86_64__)
    regs.KT_REG_PC -= sizeof(KittyTraceInsns::brkTrapInsn);
    if (!setRegs(&regs))
    {
        KITTY_LOGE("softTrapWait(%p): Failed to rewind PC!", (void *)address);
        return false;
    }
#endif

    KITTY_LOGD("softTrapWait(%p): Success PC(%p).", (void *)address, (void *)regs.KT_REG_PC);

    if (cb && !cb(regs))
    {
        if (!step())
        {
            KITTY_LOGE("softTrapWait(%p): Failed to step past breakpoint!", (void *)address);
            return false;
        }

        goto again;
    }

    return true;
}

#if 0
bool KittyTraceMgr::hardTrapWait(uintptr_t address, size_t size, KT_TRAP_TYPE type,
                                 const std::function<bool(user_regs_struct regs)> &cb)
{
    if (!_attached || _pid <= 0 || address == 0)
        return 0;

    pid_t tid = _pid;
    int status = 0;
    pid_t wp = 0;
    user_regs_struct regs = {};

#if defined(__arm__) || defined(__aarch64__)
    address &= ~3;
#endif

    auto set_watchpoint = [&]() -> bool {
#if defined(__aarch64__) || defined(__arm__)
        uint32_t control;
        switch (type)
        {
        case KT_TRAP_EXECUTE:
            control = (((1 << size) - 1) << 5) | (0 << 3) | 1;
            break;
        case KT_TRAP_READ:
            control = (((1 << size) - 1) << 5) | (1 << 3) | 1;
            break;
        case KT_TRAP_WRITE:
            control = (((1 << size) - 1) << 5) | (2 << 3) | 1;
            break;
        case KT_TRAP_ACCESS:
            control = (((1 << size) - 1) << 5) | (3 << 3) | 1;
            break;
        }

#ifdef __arm__
        return ptrace(PTRACE_SETHBPREGS, tid, -1, &address) != -1 && ptrace(PTRACE_SETHBPREGS, tid, -2, &control) != -1;
#else
        user_hwdebug_state hw;
        memset(&hw, 0, sizeof hw);

        hw.dbg_regs[0].addr = address;
        hw.dbg_regs[0].ctrl = control;

        struct iovec iov;
        iov.iov_base = &hw;
        iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(hw.dbg_regs[0]);

        return ptrace(PTRACE_SETREGSET, tid, type == KT_TRAP_EXECUTE ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH, &iov) != -1;
#endif

#elif defined(__x86_64__) || defined(__i386__)
        if (ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[0]), address) == -1)
            return false;

        unsigned long control = 0;
        switch (type)
        {
        case KT_TRAP_EXECUTE:
            control = 0;
            break;
        case KT_TRAP_WRITE:
            control = 1;
            break;
        case KT_TRAP_READ:
        case KT_TRAP_ACCESS:
            control = 3;
            break;
        }

        unsigned long len = (size == 8) ? 2 : size - 1;
        unsigned long enable = 1;
        unsigned long mask = (3UL << 18) | (3UL << 16) | (1UL << 0);
        unsigned long value = (len << 18) | (control << 16) | (enable << 0);

        unsigned long dr7 = ptrace(PTRACE_PEEKUSER, tid, offsetof(user, u_debugreg[7]), nullptr);
        dr7 &= ~mask;
        dr7 |= value;

        return ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[7]), dr7) != -1;
#endif
    };

    auto clear_watchpoint = [&]() {
#if defined(__arm__)
        ptrace(PTRACE_SETHBPREGS, tid, -1, 0);
        ptrace(PTRACE_SETHBPREGS, tid, -2, 0);

#elif defined(__aarch64__)
        user_hwdebug_state hw;
        memset(&hw, 0, sizeof hw);
        struct iovec iov = {&hw, offsetof(user_hwdebug_state, dbg_regs) + sizeof(hw.dbg_regs[0])};
        ptrace(PTRACE_SETREGSET, tid, type == KT_TRAP_EXECUTE ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH, &iov);

#elif defined(__x86_64__) || defined(__i386__)
        ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[0]), 0);
        ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[6]), 0);
        ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[7]), 0);
#endif
    };

    auto failure_return = [&]() -> bool {
        KITTY_LOGE("hardTrapWait(%p): Failed.", (void *)address);

        clear_watchpoint();
        return false;
    };

again:

    if (!set_watchpoint())
    {
        KITTY_LOGE("hardTrapWait(%p): Failed to set watchpoint!", (void *)address);
        return false;
    }

    if (!cont())
        return failure_return();

    do
    {
        errno = 0;
        status = 0;
        wp = wait(&status, WUNTRACED);
        if (wp != tid)
        {
            KITTY_LOGE("hardTrapWait(%p): waitpid returned %d. \"%s\".", (void *)address, wp, strerror(errno));
            return failure_return();
        }

        if (WIFEXITED(status))
        {
            KITTY_LOGE("hardTrapWait(%p): Target process exited (%d).", (void *)address, WEXITSTATUS(status));
            return false;
        }

        if (WIFSIGNALED(status))
        {
            KITTY_LOGE("hardTrapWait(%p): Target process terminated (%d).", (void *)address, WTERMSIG(status));
            return false;
        }

        if (!WIFSTOPPED(status))
        {
            KITTY_LOGE("hardTrapWait(%p): Target process didn't stop (status(0x%X)).", (void *)address, (status));
            return failure_return();
        }

        if (WSTOPSIG(status) == SIGSTOP)
        {
            if (!cont())
                return failure_return();

            continue;
        }

        if (!getRegs(&regs))
            return failure_return();

        if (WSTOPSIG(status) == SIGTRAP)
        {
            siginfo_t si{};
            getSignalInfo(&si);
            if (si.si_code == 4)
                break;

            KITTY_LOGE("hardTrapWait(%p): Process didn't stop at specified Hardware Breakpoint", (void *)address);
        }
        else
        {
            KITTY_LOGE("hardTrapWait(%p): Target process didn't stop with SIGTRAP", (void *)address);
        }

        KITTY_LOGE("hardTrapWait(%p): PC(%p) | RET(%p).", (void *)address, (void *)(regs.KT_REG_PC),
                   (void *)(regs.KT_REG_RET));

        siginfo_t si = {};
        getSignalInfo(&si);

        KITTY_LOGE("hardTrapWait(%p): SIG(%s) | CODE(%d) | ADDR(%p).", (void *)address, strsignal(si.si_signo),
                   si.si_code, (void *)(si.si_addr));

        auto map = KittyMemoryEx::getAddressMap(_pid, uintptr_t(si.si_addr));
        if (map.isValid())
        {
            KITTY_LOGE("hardTrapWait(%p): MAP(<base>+%p) %s", (void *)address,
                   (void *)((map.offset + uintptr_t(si.si_addr)) - map.startAddress), map.toString().c_str());
        }

        return failure_return();
    } while (true);

    KITTY_LOGD("hardTrapWait(%p): Success PC(%p).", (void *)address, (void *)regs.KT_REG_PC);

    clear_watchpoint();

    if (cb && !cb(regs))
    {
        if (!step())
        {
            KITTY_LOGE("hardTrapWait(%p): Failed to step past breakpoint!", (void *)address);
            return false;
        }

        goto again;
    }

    return true;
}
#endif