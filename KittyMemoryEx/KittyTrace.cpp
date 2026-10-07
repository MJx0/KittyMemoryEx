#include "KittyTrace.hpp"

static const char *rpCallStatusStr(KT_RP_CALL_STATUS status)
{
    switch (status)
    {
    case KT_RP_CALL_FAILED:
        return "FAILED";
    case KT_RP_CALL_SUCCESS:
        return "SUCCESS";
    case KT_RP_CALL_TIMEOUT:
        return "TIMEOUT";
    case KT_RP_CALL_EXITED:
        return "EXITED";
    case KT_RP_CALL_CONT_FAILED:
        return "CONT_FAILED";
    case KT_RP_CALL_REGS_FAILED:
        return "REGS_FAILED";
    case KT_RP_CALL_WAIT_FAILED:
        return "WAIT_FAILED";
    case KT_RP_CALL_MEM_FAILED:
        return "MEM_FAILED";
    case KT_RP_CALL_STEP_FAILED:
        return "STEP_FAILED";
    case KT_RP_CALL_NOT_STOPPED:
        return "NOT_STOPPED";
    case KT_RP_CALL_MISMATCH_STOP:
        return "MISMATCH_STOP";
    }

    return "UNKNOWN";
}

static const char *bpResultStr(KT_BP_RESULT result)
{
    switch (result)
    {
    case KT_BP_FAILED:
        return "FAILED";
    case KT_BP_SUCCESS:
        return "SUCCESS";
    case KT_BP_TIMEOUT:
        return "TIMEOUT";
    case KT_BP_EXITED:
        return "EXITED";
    case KT_BP_CONT_FAILED:
        return "CONT_FAILED";
    case KT_BP_STEP_FAILED:
        return "STEP_FAILED";
    case KT_BP_REGS_FAILED:
        return "REGS_FAILED";
    case KT_BP_WAIT_FAILED:
        return "WAIT_FAILED";
    case KT_BP_MEM_FAILED:
        return "MEM_FAILED";
    case KT_BP_NOT_STOPPED:
        return "NOT_STOPPED";
    case KT_BP_MISMATCH_STOP:
        return "MISMATCH_STOP";
    }

    return "UNKNOWN";
}

static const char *siCodeStr(int signo, int code)
{
    switch (code)
    {
    case SI_USER:
        return "SI_USER";
#ifdef SI_KERNEL
    case SI_KERNEL:
        return "SI_KERNEL";
#endif
    case SI_QUEUE:
        return "SI_QUEUE";
    case SI_TIMER:
        return "SI_TIMER";
    case SI_TKILL:
        return "SI_TKILL";
    default:
        break;
    }

    if (signo == SIGTRAP)
    {
        switch (code)
        {
        case TRAP_BRKPT:
            return "TRAP_BRKPT";
        case TRAP_TRACE:
            return "TRAP_TRACE";
        case TRAP_BRANCH:
            return "TRAP_BRANCH";
        case TRAP_HWBKPT:
            return "TRAP_HWBKPT";
        }
    }
    else if (signo == SIGSEGV)
    {
        switch (code)
        {
        case SEGV_MAPERR:
            return "SEGV_MAPERR";
        case SEGV_ACCERR:
            return "SEGV_ACCERR";
        }
    }
    else if (signo == SIGBUS)
    {
        switch (code)
        {
        case BUS_ADRALN:
            return "BUS_ADRALN";
        case BUS_ADRERR:
            return "BUS_ADRERR";
        case BUS_OBJERR:
            return "BUS_OBJERR";
        }
    }
    else if (signo == SIGILL)
    {
        switch (code)
        {
        case ILL_ILLOPC:
            return "ILL_ILLOPC";
        case ILL_ILLOPN:
            return "ILL_ILLOPN";
        case ILL_ILLADR:
            return "ILL_ILLADR";
        case ILL_PRVOPC:
            return "ILL_PRVOPC";
        }
    }

    return "?";
}

static void logFaultContext(pid_t pid, const char *prefix, const user_regs_struct &regs)
{
    siginfo_t si = {};
    ptrace(PTRACE_GETSIGINFO, pid, 0, &si);

#if defined(__aarch64__) || defined(__arm__)
    KITTY_LOGE("%s: Regs PC=%p LR=%p SP=%p RET=%p",
               prefix,
               (void *)regs.KT_REG_PC,
               (void *)regs.KT_REG_LR,
               (void *)regs.KT_REG_SP,
               (void *)regs.KT_REG_RET);
#else
    KITTY_LOGE("%s: Regs PC=%p SP=%p RET=%p",
               prefix,
               (void *)regs.KT_REG_PC,
               (void *)regs.KT_REG_SP,
               (void *)regs.KT_REG_RET);
#endif

    KITTY_LOGE("%s: Signal %s (si_signo=%d, si_code=%s[%d], si_addr=%p)",
               prefix,
               strsignal(si.si_signo),
               si.si_signo,
               siCodeStr(si.si_signo, si.si_code),
               si.si_code,
               (void *)si.si_addr);

    auto fmap = KittyMemoryEx::getAddressMap(pid, uintptr_t(si.si_addr));
    if (fmap.isValid())
        KITTY_LOGE("%s: Fault addr in map <base>+%p %s",
                   prefix,
                   (void *)((fmap.offset + uintptr_t(si.si_addr)) - fmap.startAddress),
                   fmap.toString().c_str());

    auto pcmap = KittyMemoryEx::getAddressMap(pid, uintptr_t(regs.KT_REG_PC));
    if (pcmap.isValid())
        KITTY_LOGE("%s: PC in map <base>+%p %s",
                   prefix,
                   (void *)((pcmap.offset + uintptr_t(regs.KT_REG_PC)) - pcmap.startAddress),
                   pcmap.toString().c_str());
}

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
        KITTY_LOGE("PTRACE_ATTACH failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
        return false;
    }

    _seized = false;

    int status;
    if (KT_EINTR_RETRY(waitpid(_pid, &status, 0)) != _pid || !WIFSTOPPED(status))
    {
        KITTY_LOGE("Error occurred while waiting for pid %d to stop. strerror=\"%s\".", _pid, strerror(errno));
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
        KITTY_LOGE("PTRACE_SEIZE failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
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
        KITTY_LOGE("PTRACE_SETOPTIONS failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
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
        KITTY_LOGE("PTRACE_DETACH failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
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
            KITTY_LOGE("PTRACE_INTERRUPT failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
            return false;
        }
    }
    else
    {
        if (tgkill(_pid, _pid, SIGSTOP) == -1)
        {
            KITTY_LOGE("tgkill failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
            return false;
        }
    }

    int status;
    if (KT_EINTR_RETRY(waitpid(_pid, &status, 0)) != _pid || !WIFSTOPPED(status))
    {
        KITTY_LOGE("Error occurred while waiting for pid %d to stop. strerror=\"%s\".", _pid, strerror(errno));
        return false;
    }

    // Drain stacked stop notifications (e.g. a group-stop alongside our INTERRUPT) so a
    // later wait isn't desynced; reaping them doesn't resume the tracee.
    while (waitpid(_pid, nullptr, __WALL | WNOHANG) > 0)
        ;

    return true;
}

bool KittyTraceMgr::cont(int sig)
{
    if (!_attached || _pid <= 0)
        return false;

    errno = 0;
    if (ptrace(PTRACE_CONT, _pid, nullptr, sig) == -1L)
    {
        KITTY_LOGE("PTRACE_CONT failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
        return false;
    }

    return true;
}

pid_t KittyTraceMgr::wait(int *status, int options, int timeout_ms) const
{
    if (!_attached)
        return -1;

    if (timeout_ms <= 0)
        return KT_EINTR_RETRY(waitpid(_pid, status, options));

    int elapsed = 0;
    pid_t res;
    if (!(options & WNOHANG))
        options |= WNOHANG;

    while (elapsed < timeout_ms)
    {
        res = KT_EINTR_RETRY(waitpid(_pid, status, options));
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
        KITTY_LOGE("PTRACE_SYSCALL failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
        return false;
    }

    int status = 0;
    KT_EINTR_RETRY(waitpid(_pid, &status, 0));
    if (!WIFSTOPPED(status))
    {
        KITTY_LOGE("waitSyscall: pid %d did not stop after PTRACE_SYSCALL (status=0x%x).", _pid, status);
        return false;
    }

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
            KITTY_LOGE("PTRACE_SINGLESTEP failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
            return false;
        }

        if ((i + 1) < steps)
        {
            KT_EINTR_RETRY(waitpid(_pid, &status, 0));
            if (!WIFSTOPPED(status))
            {
                KITTY_LOGE("step: pid %d did not stop after single-step %d/%d (status=0x%x).",
                           _pid,
                           i + 1,
                           steps,
                           status);
                return false;
            }
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
            KITTY_LOGE("PTRACE_SINGLESTEP failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
            return false;
        }

        KT_EINTR_RETRY(waitpid(_pid, &status, 0));
        if (!WIFSTOPPED(status))
        {
            KITTY_LOGE("waitStep: pid %d did not stop after single-step %d/%d (status=0x%x).",
                       _pid,
                       i + 1,
                       steps,
                       status);
            return false;
        }
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
        KITTY_LOGE("PTRACE_GETREGS failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
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
        KITTY_LOGE("PTRACE_SETREGS failed for pid %d. strerror=\"%s\".", _pid, strerror(errno));
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

    std::string ctx = KittyUtils::String::fmt("callFunction(pid(%d), addr(%p))", _pid, (void *)functionAddress);

    user_regs_struct backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));

    // backup current regs
    if (!getRegs(&backup_regs))
    {
        KITTY_LOGE("%s: Failed, couldn't get regs.", ctx.c_str());
        return {KT_RP_CALL_REGS_FAILED, {0}};
    }

    memcpy(&tmp_regs, &backup_regs, sizeof(backup_regs));

    KT_REGS_ALIGN_STACK(tmp_regs);

    KITTY_LOGD("%s: Calling with %d args.", ctx.c_str(), nargs);

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
        KITTY_LOGE("%s: Failed (%s).", ctx.c_str(), rpCallStatusStr(s));
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
#if defined(__aarch64__)
    // Clear Single-step (Bit 21) and Debug Exception (Bit 9)
    tmp_regs.pstate &= ~KT_CPSR_SS_MASK;
    tmp_regs.pstate &= ~KT_CPSR_D_MASK;

    // Clear BTYPE (Bits 10 & 11) to bypass BTI enforcement
    tmp_regs.pstate &= ~KT_CPSR_BTYPE_MASK;
#elif defined(__arm__)
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
                KITTY_LOGE("%s: Timed out!", ctx.c_str());
                return failure_return(KT_RP_CALL_TIMEOUT);
            }

            KITTY_LOGE("%s: waitpid returned %d. strerror=\"%s\".", ctx.c_str(), wp, strerror(errno));
            return failure_return(KT_RP_CALL_WAIT_FAILED);
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("%s: Target process exited (status %d).", ctx.c_str(), WEXITSTATUS(status));
            return {KT_RP_CALL_EXITED, {0}};
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("%s: Target process killed by signal %s.", ctx.c_str(), strsignal(WTERMSIG(status)));
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

        KITTY_LOGD("%s: Ok.", ctx.c_str());

        if (validate_ret(return_regs, callerAddress))
            break;

        // An asynchronous signal (sent via kill/sigqueue/tgkill, si_code <= 0 - e.g.
        // the runtime's SIGRTMIN+x) delivered to the thread mid-call is NOT our return and
        // does not mean the call failed. We must NOT run its handler: the thread is hijacked
        // (fake stack, LR=sentinel), so the handler would execute in an invalid context.
        // Suppress it (cont with sig 0) and keep waiting for the call to finish.
        // Only a synchronous fault (si_code > 0) at a non-caller PC is a genuine crash.
        siginfo_t si = {};
        getSignalInfo(&si);
        if (si.si_code <= 0)
        {
            if (!cont(0)) // suppress: do not run a handler on the hijacked thread
                return failure_return(KT_RP_CALL_CONT_FAILED);
            continue;
        }

        KITTY_LOGE("%s: Process did not return to caller %p after the call (PC=%p, StopSig=%s).",
                   ctx.c_str(),
                   (void *)callerAddress,
                   (void *)return_regs.KT_REG_PC,
                   strsignal(WSTOPSIG(status)));
        logFaultContext(_pid, ctx.c_str(), return_regs);

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

    std::string ctx = KittyUtils::String::fmt("callSyscall(pid(%d), sysnr(%d))", _pid, int(sysnr));

    user_regs_struct backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));

    // backup current regs
    if (!getRegs(&backup_regs))
    {
        KITTY_LOGE("%s: Failed, couldn't get regs.", ctx.c_str());
        return {KT_RP_CALL_REGS_FAILED, {0}};
    }

    memcpy(&tmp_regs, &backup_regs, sizeof(backup_regs));

    KT_REGS_ALIGN_STACK(tmp_regs);

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

    // Run the syscall with PTRACE_SYSCALL:
    // resume to the syscall-entry stop, then to the syscall-exit stop.
    // When a gadget is set we execute its svc and modify no target memory
    // otherwise we temporarily place a svc at the current PC and restore it afterwards.
    uintptr_t target_pc_mem = tmp_regs.KT_REG_PC;

#if defined(__arm__)
    // Thumb mode: from the gadget's low bit if a gadget is set, else from PC / CPSR.
    bool thumb = _syscallGadget != 0 ? (_syscallGadget & 1) != 0
                                     : ((target_pc_mem & 1) != 0 || (tmp_regs.KT_REG_CPSR & KT_CPSR_T_MASK) != 0);
#endif

    // Syscall instruction encoding for this arch/mode.
    std::vector<uint8_t> syscall_insn;
#if defined(__arm__)
    if (thumb)
        syscall_insn.assign(std::begin(KittyTraceInsns::THUMB_SYSCALL), std::end(KittyTraceInsns::THUMB_SYSCALL));
    else
        syscall_insn.assign(std::begin(KittyTraceInsns::SYSCALL), std::end(KittyTraceInsns::SYSCALL));
#else
    syscall_insn.assign(std::begin(KittyTraceInsns::SYSCALL), std::end(KittyTraceInsns::SYSCALL));
#endif

    // Where the svc runs. With a gadget nothing is written; otherwise we patch the PC.
    uintptr_t exec_addr = _syscallGadget != 0 ? _syscallGadget : target_pc_mem;
#if defined(__arm__)
    exec_addr &= ~uintptr_t(1); // strip the thumb bit; mode is carried in CPSR.T
#endif

    const bool wrote_syscall = _syscallGadget == 0;
    std::vector<uint8_t> backup_code;
    if (wrote_syscall)
    {
        if (!KittyMemoryEx::getAddressMap(_pid, exec_addr).executable)
        {
            KITTY_LOGE("%s: PC %p is not in executable memory!", ctx.c_str(), (void *)exec_addr);
            return {KT_RP_CALL_MEM_FAILED, {0}};
        }

        backup_code.resize(syscall_insn.size(), 0);
        if (!peekMem(exec_addr, backup_code.data(), backup_code.size()))
        {
            KITTY_LOGE("%s: Failed to back up code at %p.", ctx.c_str(), (void *)exec_addr);
            return {KT_RP_CALL_MEM_FAILED, {0}};
        }
    }

    // cleanup failure return
    auto failure_return = [&](KT_RP_CALL_STATUS s = KT_RP_CALL_FAILED) -> kitty_rp_call_t {
        KITTY_LOGE("%s: Failed (%s).", ctx.c_str(), rpCallStatusStr(s));

        if (_autoRestoreRegs)
            setRegs(&backup_regs);

        if (wrote_syscall)
            pokeMem(exec_addr, backup_code.data(), backup_code.size());
        return {s, {0}};
    };

    tmp_regs.KT_REG_PC = exec_addr;

#if defined(__aarch64__)
    // Clear BTYPE (Bits 10 & 11) to bypass BTI enforcement at the syscall instruction.
    tmp_regs.pstate &= ~KT_CPSR_BTYPE_MASK;
#elif defined(__arm__)
    if (thumb)
        tmp_regs.KT_REG_CPSR |= KT_CPSR_T_MASK;
    else
        tmp_regs.KT_REG_CPSR &= ~KT_CPSR_T_MASK;
#endif

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

    // For the no-gadget fallback, temporarily write a svc at the current PC.
    if (wrote_syscall)
    {
        if (!pokeMem(exec_addr, syscall_insn.data(), syscall_insn.size()))
        {
            KITTY_LOGE("%s: Failed to write svc at %p.", ctx.c_str(), (void *)exec_addr);
            return failure_return(KT_RP_CALL_MEM_FAILED);
        }
    }

    // Set new registers
    if (!setRegs(&tmp_regs))
        return failure_return(KT_RP_CALL_REGS_FAILED);

    // Execute one syscall via two PTRACE_SYSCALL stops (entry, exit)
    // result is then in the result register.
    // Group-stops/benign signals are dropped, real signals re-delivered.
    int phase = 0;       // 0: awaiting syscall-entry, 1: awaiting syscall-exit
    int deliver_sig = 0; // signal to re-inject on the next resume
    while (phase < 2)
    {
        errno = 0;
        if (ptrace(PTRACE_SYSCALL, _pid, nullptr, (void *)(intptr_t)deliver_sig) == -1L)
        {
            KITTY_LOGE("%s: PTRACE_SYSCALL failed. strerror=\"%s\".", ctx.c_str(), strerror(errno));
            return failure_return(KT_RP_CALL_CONT_FAILED);
        }
        deliver_sig = 0;

        int status = 0;
        pid_t wp = wait(&status, __WALL);
        if (wp != _pid)
        {
            KITTY_LOGE("%s: waitpid returned %d. strerror=\"%s\".", ctx.c_str(), wp, strerror(errno));
            return failure_return(KT_RP_CALL_WAIT_FAILED);
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("%s: Target process exited (status %d).", ctx.c_str(), WEXITSTATUS(status));
            return {KT_RP_CALL_EXITED, {0}};
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("%s: Target process killed by signal %d.", ctx.c_str(), WTERMSIG(status));
            return {KT_RP_CALL_EXITED, {0}};
        }

        if (!WIFSTOPPED(status))
            continue;

        const int sig = WSTOPSIG(status);

        // syscall-entry / syscall-exit stop. With PTRACE_O_TRACESYSGOOD the kernel
        // sets bit 7; without it a syscall stop is a plain SIGTRAP, which in this
        // controlled run at a svc can only be our own syscall stop.
        if (sig == (SIGTRAP | 0x80) || sig == SIGTRAP)
        {
            ++phase;
            continue;
        }

        // group-stop (seized) / job-control signals: resume, drop the signal.
        if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU || sig == SIGCHLD)
            continue;

        // The thread is hijacked (gadget svc / fake regs), so its handler must not run here.
        // An async signal (si_code<=0, e.g. a runtime SIGRTMIN+x) is unrelated to our syscall:
        // suppress it and keep waiting. A synchronous fault (si_code>0) is a real problem with
        // the syscall itself - re-deliver it so it surfaces rather than being masked.
        siginfo_t si = {};
        getSignalInfo(&si);
        deliver_sig = si.si_code <= 0 ? 0 : sig;
    }

    if (!getRegs(&return_regs))
        return failure_return(KT_RP_CALL_REGS_FAILED);

    kitty_rp_call_t result = {KT_RP_CALL_SUCCESS, {static_cast<intptr_t>(return_regs.KT_REG_RET)}};

    // Restore the code we patched in (no-op when using the gadget).
    if (wrote_syscall && !pokeMem(exec_addr, backup_code.data(), backup_code.size()))
        KITTY_LOGW("%s: Failed to restore code at %p!", ctx.c_str(), (void *)exec_addr);

    // Restore regs
    if (_autoRestoreRegs)
        setRegs(&backup_regs);

    KITTY_LOGD("%s: Returned %p.", ctx.c_str(), (void *)result.result.ptr);
    return result;
}

KT_BP_RESULT KittyTraceMgr::setSoftBreakpointAndWait(uintptr_t address,
                                                     const std::function<bool(uintptr_t bp_addr, user_regs_struct regs)> &cb,
                                                     int timeout_ms)
{
    if (!_attached || _pid <= 0 || address == 0)
        return KT_BP_FAILED;

    std::string ctx = KittyUtils::String::fmt("setSoftBreakpointAndWait(pid(%d), addr(%p))", _pid, (void *)address);

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

    // Size the patch to the opcode length, else poking a wider buffer zeroes the following
    // instruction (SEGV on x86, SIGILL on arm64).
#if defined(__arm__)
    const size_t bp_size = thumb ? sizeof(KittyTraceInsns::THUMB_BRKP) : sizeof(KittyTraceInsns::BRKP);
#else
    const size_t bp_size = sizeof(KittyTraceInsns::BRKP);
#endif
    std::vector<uint8_t> brk_code(bp_size, 0);
    std::vector<uint8_t> bak_code(bp_size, 0);
    int status = 0;
    pid_t wp = 0;
    user_regs_struct regs = {};

    // cleanup failure return
    auto failure_return = [&](KT_BP_RESULT res = KT_BP_FAILED) -> KT_BP_RESULT {
        KITTY_LOGE("%s: Failed (%s).", ctx.c_str(), bpResultStr(res));
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
        KITTY_LOGE("%s: Failed to backup memory code.", ctx.c_str());
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
        KITTY_LOGE("%s: Failed to write brk code into memory.", ctx.c_str());
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
                KITTY_LOGE("%s: Timed out!", ctx.c_str());
                pokeMem(address, bak_code.data(), bak_code.size());
                return KT_BP_TIMEOUT;
            }

            KITTY_LOGE("%s: waitpid returned %d. strerror=\"%s\".", ctx.c_str(), wp, strerror(errno));

            return failure_return(KT_BP_WAIT_FAILED);
        }

        if (WIFEXITED(status))
        {
            _attached = false;
            KITTY_LOGE("%s: Target process exited (%d).", ctx.c_str(), WEXITSTATUS(status));
            return KT_BP_EXITED;
        }

        if (WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("%s: Target process terminated (%d).", ctx.c_str(), WTERMSIG(status));
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

        std::string ctx = KittyUtils::String::fmt("setSoftBreakpointAndWait(pid(%d), addr(%p))", _pid, (void *)address);
        if (WSTOPSIG(status) == SIGTRAP)
        {
            if (validate_trap(regs, address))
                break;

            KITTY_LOGE("%s: Stopped on SIGTRAP not at the breakpoint (PC=%p).", ctx.c_str(), (void *)regs.KT_REG_PC);
        }
        else
        {
            // An asynchronous signal (kill/sigqueue/tgkill, si_code <= 0 - e.g. a runtime
            // SIGRTMIN+x) just means the thread hasn't reached the breakpoint yet: forward it
            // and keep waiting. Only a synchronous fault (si_code > 0) is a real failure.
            siginfo_t si = {};
            getSignalInfo(&si);
            if (si.si_code <= 0)
            {
                if (!cont(WSTOPSIG(status)))
                    return failure_return(KT_BP_CONT_FAILED);
                continue;
            }

            KITTY_LOGE("%s: Stopped with unexpected signal %s (expected SIGTRAP at the breakpoint).",
                       ctx.c_str(),
                       strsignal(WSTOPSIG(status)));
        }

        logFaultContext(_pid, ctx.c_str(), regs);

        if (!cont(WSTOPSIG(status)))
            return failure_return(KT_BP_CONT_FAILED);

        return failure_return(KT_BP_MISMATCH_STOP);

    } while (true);

    if (!pokeMem(address, bak_code.data(), bak_code.size()))
    {
        KITTY_LOGE("%s: Failed to restore memory code!", ctx.c_str());
        return KT_BP_MEM_FAILED;
    }

#if defined(__i386__) || defined(__x86_64__)
    regs.KT_REG_PC -= sizeof(KittyTraceInsns::BRKP);
    if (!setRegs(&regs))
    {
        KITTY_LOGE("%s: Failed to rewind PC!", ctx.c_str());
        return KT_BP_REGS_FAILED;
    }
#endif

    KITTY_LOGD("%s: Success PC(%p).", ctx.c_str(), (void *)regs.KT_REG_PC);

    if (cb && !cb(address, regs))
    {
        // Restore done above; single-step over the original instruction, then re-arm.
        if (!waitStep())
        {
            KITTY_LOGE("%s: Failed to step past breakpoint!", ctx.c_str());
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
                                                     const std::function<bool(uintptr_t bp_addr, user_regs_struct regs)> &cb,
                                                     int timeout_ms)
{
    if (!_attached || _pid <= 0 || address == 0)
        return KT_BP_FAILED;

    std::string ctx = KittyUtils::String::fmt("setHardBreakpointAndWait(pid(%d), addr(%p))", _pid, (void *)address);

    const char *kind = type == KT_HW_BP_EXECUTE ? "breakpoint" : "watchpoint";
    pid_t tid = _pid;
    int status = 0;
    pid_t wp = 0;
    user_regs_struct regs = {};

    // Execute breakpoints pick their width from the address (thumb vs ARM on arm32);
    // watchpoints use the caller's size.
#if defined(__arm__)
    KT_HW_BP_SIZE bp_size = type != KT_HW_BP_EXECUTE ? size : ((address & 1) != 0 ? KT_HW_BP_SIZE_2 : KT_HW_BP_SIZE_4);
#elif defined(__aarch64__)
    KT_HW_BP_SIZE bp_size = type != KT_HW_BP_EXECUTE ? size : KT_HW_BP_SIZE_4;
#else
    KT_HW_BP_SIZE bp_size = type != KT_HW_BP_EXECUTE ? size : KT_HW_BP_SIZE_1;
#endif

    auto failure_return = [&](KT_BP_RESULT res = KT_BP_FAILED) -> KT_BP_RESULT {
        KITTY_LOGE("%s: Failed (%s).", ctx.c_str(), bpResultStr(res));
        clearHwBreakpoint(type, slot);
        return res;
    };

    // A hit is ours if the kernel flagged a hw debug trap (TRAP_HWBKPT - the reliable check
    // for watchpoints, where si_addr is the accessing instruction) or the PC/si_addr landed
    // on the breakpoint address.
    auto is_our_trap = [this, bp_size](const user_regs_struct &r, uintptr_t trap_addr) -> bool {
        siginfo_t si = {};
        getSignalInfo(&si);
        if (si.si_code == TRAP_HWBKPT)
            return true;

        trap_addr = (trap_addr & ~uintptr_t(1)) & ~(sizeof(uintptr_t) - 1);
        uintptr_t pc = uintptr_t(r.KT_REG_PC) & ~uintptr_t(1);
        uintptr_t top = KT_ALIGN_UP(trap_addr + std::max(int(bp_size), int(sizeof(KittyTraceInsns::BRKP))),
                                    int(sizeof(uintptr_t)));
        return (pc >= trap_addr && pc <= top) || (uintptr_t(si.si_addr) >= trap_addr && uintptr_t(si.si_addr) <= top);
    };

again:

    if (!setHwBreakpoint(address, type, bp_size, slot))
    {
        KITTY_LOGE("%s: Failed to set %s. strerror=\"%s\".", ctx.c_str(), kind, strerror(errno));
        return KT_BP_FAILED;
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
                KITTY_LOGE("%s: Timed out waiting.", ctx.c_str());
                clearHwBreakpoint(type, slot);
                return KT_BP_TIMEOUT;
            }

            KITTY_LOGE("%s: waitpid returned %d. strerror=\"%s\".", ctx.c_str(), wp, strerror(errno));
            return failure_return(KT_BP_WAIT_FAILED);
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("%s: Target process %s before the %s was hit.",
                       ctx.c_str(),
                       WIFEXITED(status) ? "exited" : "was killed by a signal",
                       kind);
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
            if (is_our_trap(regs, address))
                break;

            KITTY_LOGE("%s: Stopped on SIGTRAP not at the breakpoint (got PC=%p).",
                       ctx.c_str(),
                       (void *)regs.KT_REG_PC);
        }
        else
        {
            KITTY_LOGE("%s: Stopped with unexpected signal %s (expected SIGTRAP at the breakpoint).",
                       ctx.c_str(),
                       strsignal(WSTOPSIG(status)));
        }

        logFaultContext(_pid, ctx.c_str(), regs);

        if (!cont(WSTOPSIG(status)))
            return failure_return(KT_BP_CONT_FAILED);

        // Don't fail: a hw trap can land at a nearby PC, so forward the signal and keep waiting.

    } while (true);

    clearHwBreakpoint(type, slot);

    if (cb && !cb(address, regs))
    {
        if (!waitStep())
        {
            KITTY_LOGE("%s: Failed to step past the %s.",
                       ctx.c_str(),
                       kind);
            return KT_BP_STEP_FAILED;
        }
        goto again;
    }

    KITTY_LOGD("%s: Hit at PC %p.", ctx.c_str(), _pid, (void *)regs.KT_REG_PC);
    return KT_BP_SUCCESS;
}

KT_BP_RESULT KittyTraceMgr::setHardExecBreakpointsAndWait(const std::vector<uintptr_t> &addresses,
                                                          const std::function<bool(uintptr_t bp_addr, user_regs_struct regs)> &cb,
                                                          int timeout_ms)
{
    if (!_attached || _pid <= 0)
        return KT_BP_FAILED;

    std::vector<uintptr_t> addrs;
    for (uintptr_t a : addresses)
        if (a && addrs.size() < 4)
            addrs.push_back(a);

    if (addrs.empty())
        return KT_BP_FAILED;

    pid_t tid = _pid;
    user_regs_struct regs = {};
    uintptr_t at_bp = 0;

    auto arm_all = [&]() -> bool {
        for (size_t i = 0; i < addrs.size(); i++)
        {
#if defined(__arm__)
            KT_HW_BP_SIZE sz = (addrs[i] & 1) != 0 ? KT_HW_BP_SIZE_2 : KT_HW_BP_SIZE_4;
#elif defined(__aarch64__)
            KT_HW_BP_SIZE sz = KT_HW_BP_SIZE_4;
#else
            KT_HW_BP_SIZE sz = KT_HW_BP_SIZE_1;
#endif
            if (!setHwBreakpoint(addrs[i], KT_HW_BP_EXECUTE, sz, int(i)))
            {
                KITTY_LOGE("setHardExecBreakpointsAndWait: Failed to set breakpoint %zu at %p. strerror=\"%s\".",
                           i,
                           (void *)addrs[i],
                           strerror(errno));
                return false;
            }
        }
        return true;
    };

    auto clear_all = [&]() {
        // Reverse order: on arm64 a slot is cleared via a GETREGSET/SETREGSET that spans
        // slots 0..n, so clearing the highest slot first keeps each lower clear from being
        // resurrected by a later multi-slot read.
        for (int i = int(addrs.size()) - 1; i >= 0; i--)
            clearHwBreakpoint(KT_HW_BP_EXECUTE, i);
    };

    auto at_any_bp = [&](uintptr_t pc) -> uintptr_t {
        pc &= ~uintptr_t(1);
        for (uintptr_t a : addrs)
        {
            uintptr_t base = (a & ~uintptr_t(1)) & ~(sizeof(uintptr_t) - 1);
            uintptr_t top = KT_ALIGN_UP(base + sizeof(KittyTraceInsns::BRKP), int(sizeof(uintptr_t)));
            if (pc >= base && pc <= top)
                return a;
        }
        return 0;
    };

again:

    if (!arm_all())
    {
        clear_all();
        return KT_BP_FAILED;
    }

    if (!cont())
    {
        clear_all();
        return KT_BP_CONT_FAILED;
    }

    for (;;)
    {
        errno = 0;
        int status = 0;
        pid_t wp = wait(&status, WUNTRACED, timeout_ms);
        if (wp != tid)
        {
            if (wp == 0)
            {
                stop();
                KITTY_LOGE("setHardExecBreakpointsAndWait: Timed out waiting for pid %d.", _pid);
                clear_all();
                return KT_BP_TIMEOUT;
            }

            KITTY_LOGE("setHardExecBreakpointsAndWait: waitpid returned %d for pid %d. strerror=\"%s\".",
                       wp,
                       _pid,
                       strerror(errno));
            clear_all();
            return KT_BP_WAIT_FAILED;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
        {
            _attached = false;
            KITTY_LOGE("setHardExecBreakpointsAndWait: Target pid %d %s before any breakpoint hit.",
                       _pid,
                       WIFEXITED(status) ? "exited" : "was terminated");
            return KT_BP_EXITED;
        }

        if (!WIFSTOPPED(status))
            continue;

        const int sig = WSTOPSIG(status);
        if (sig == SIGCHLD || sig == SIGSTOP || sig == SIGTSTP)
        {
            if (!cont())
            {
                clear_all();
                return KT_BP_CONT_FAILED;
            }
            continue;
        }

        if (!getRegs(&regs))
        {
            clear_all();
            return KT_BP_REGS_FAILED;
        }

        at_bp = at_any_bp(regs.KT_REG_PC);

        siginfo_t si = {};
        getSignalInfo(&si);
        if (sig == SIGTRAP && (si.si_code == TRAP_HWBKPT || at_bp != 0))
            break;

        // Not one of our breakpoints: forward the signal and keep waiting.
        logFaultContext(_pid, "setHardExecBreakpointsAndWait", regs);
        if (!cont(sig))
        {
            clear_all();
            return KT_BP_CONT_FAILED;
        }
    }

    clear_all();

    if (cb && !cb(at_bp, regs))
    {
        if (!waitStep())
        {
            KITTY_LOGE("setHardExecBreakpointsAndWait: Failed to step past the breakpoint on pid %d.", _pid);
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
    // ARM PTRACE_*HBPREGS index convention: breakpoints use positive register
    // numbers (value=2N+1, control=2N+2), watchpoints use the negated form.
    long vr_idx = type == KT_HW_BP_EXECUTE ? ((slot * 2) + 1) : -((slot * 2) + 1);
    long cr_idx = type == KT_HW_BP_EXECUTE ? ((slot * 2) + 2) : -((slot * 2) + 2);
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
    if (ptrace(PTRACE_POKEUSER,
               tid,
               offsetof(struct user, u_debugreg) + slot * sizeof(((struct user *)0)->u_debugreg[0]),
               address) == -1L)
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
    // ARM PTRACE_*HBPREGS index convention: breakpoints use positive register
    // numbers (value=2N+1, control=2N+2), watchpoints use the negated form.
    long vr_idx = type == KT_HW_BP_EXECUTE ? ((slot * 2) + 1) : -((slot * 2) + 1);
    long cr_idx = type == KT_HW_BP_EXECUTE ? ((slot * 2) + 2) : -((slot * 2) + 2);
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

    if (ptrace(PTRACE_POKEUSER,
               tid,
               offsetof(struct user, u_debugreg) + slot * sizeof(((struct user *)0)->u_debugreg[0]),
               0) == -1L)
        return false;

    ptrace(PTRACE_POKEUSER, tid, offsetof(struct user, u_debugreg[6]), 0);

    return true;
#endif
}
