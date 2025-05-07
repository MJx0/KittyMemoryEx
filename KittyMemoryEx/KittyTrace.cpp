#include "KittyTrace.hpp"

#if defined(__aarch64__)
#define kREG_ARGS_NUM 8
#define uregs regs
#define r0 regs[0]
#define lr regs[30]
#define cpsr pstate

#elif defined(__arm__)
#define kREG_ARGS_NUM 4
#define sp ARM_sp
#define pc ARM_pc
#define r0 ARM_r0
#define lr ARM_lr
#define cpsr ARM_cpsr
#endif

bool KittyTraceMgr::Attach() const
{
    if (remotePID() <= 0)
        return false;

    if (isAttached())
        return true;

    errno = 0;
    if (ptrace(PTRACE_ATTACH, remotePID(), nullptr, nullptr) == -1L)
    {
        KITTY_LOGE("PTRACE_ATTACH failed for pid %d. error=\"%s\".", remotePID(), strerror(errno));
        return false;
    }

    int status;
    if (Wait(&status, 0) != remotePID() || !WIFSTOPPED(status))
    {
        KITTY_LOGE("Error occurred while waiting for pid %d to stop. error=\"%s\".", remotePID(), strerror(errno));
        ptrace(PTRACE_DETACH, remotePID(), nullptr, nullptr);
        return false;
    }
    return true;
}

bool KittyTraceMgr::Detach() const
{
    if (!isAttached())
        return true;

    errno = 0;
    if (ptrace(PTRACE_DETACH, remotePID(), nullptr, nullptr) == -1L)
    {
        KITTY_LOGE("PTRACE_DETACH failed for pid %d. error=\"%s\".", remotePID(), strerror(errno));
        return false;
    }

    return true;
}

bool KittyTraceMgr::Cont() const
{
    if (!isAttached())
    {
        KITTY_LOGE("PTRACE_CONT failed, Not attached to %d.", remotePID());
        return false;
    }

    errno = 0;
    if (ptrace(PTRACE_CONT, remotePID(), nullptr, nullptr) == -1L)
    {
        KITTY_LOGE("PTRACE_CONT failed for pid %d. error=\"%s\".", remotePID(), strerror(errno));
        return false;
    }
    return true;
}

bool KittyTraceMgr::getRegs(pt_regs *regs) const
{
    if (!regs)
        return false;

    if (!isAttached())
    {
        KITTY_LOGE("PTRACE_GETREGS failed, Not attached to %d.", remotePID());
        return false;
    }

    errno = 0;

#if defined(__LP64__)
    iovec ioVec;
    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    long ret = ptrace(PTRACE_GETREG_REQ, remotePID(), NT_PRSTATUS, &ioVec);
#else
    long ret = ptrace(PTRACE_GETREG_REQ, remotePID(), nullptr, regs);
#endif
    if (ret == -1L)
    {
        KITTY_LOGE("PTRACE_GETREGS failed for pid %d. error=\"%s\".", remotePID(), strerror(errno));
        return false;
    }
    return true;
}

bool KittyTraceMgr::setRegs(pt_regs *regs) const
{
    if (!regs)
        return false;

    if (!isAttached())
    {
        KITTY_LOGE("PTRACE_SETREGS failed, Not attached to %d.", remotePID());
        return false;
    }

    errno = 0;

#if defined(__LP64__)
    iovec ioVec;
    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    long ret = ptrace(PTRACE_SETREG_REQ, remotePID(), NT_PRSTATUS, &ioVec);
#else
    long ret = ptrace(PTRACE_SETREG_REQ, remotePID(), nullptr, regs);
#endif
    if (ret == -1L)
    {
        KITTY_LOGE("PTRACE_SETREGS failed for pid %d. error=\"%s\".", remotePID(), strerror(errno));
        return false;
    }
    return true;
}

// refs
// https://github.com/evilsocket/arminject
// https://github.com/Chainfire/injectvm-binderjack
// https://github.com/shunix/TinyInjector
// https://github.com/topjohnwu/Magisk/blob/master/native/src/zygisk/ptrace.cpp

uintptr_t KittyTraceMgr::callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, int nargs, ...) const
{
    if (!functionAddress)
        return 0;

    if (!isAttached())
    {
        KITTY_LOGE("callFunction failed, Not attached to %d.", remotePID());
        return 0;
    }

    pt_regs backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));

    // backup current regs
    if (!getRegs(&backup_regs))
        return 0;

    memcpy(&tmp_regs, &backup_regs, sizeof(backup_regs));

    // cleanup failure return
    auto failure_return = [&]() -> uintptr_t
    {
        KITTY_LOGE("callFunction: Failed to call function %p with %d args.", (void *)functionAddress, nargs);
        if (_autoRestoreRegs)
            setRegs(&backup_regs);
        return 0;
    };

    KITTY_LOGD("callFunction: Calling function %p with %d args.", (void *)functionAddress, nargs);

    va_list vl;
    va_start(vl, nargs);

#if defined(__arm__) || defined(__aarch64__)

    // Fill R0-Rx with the first 4 (32-bit) or 8 (64-bit) parameters
    for (int i = 0; (i < nargs) && (i < kREG_ARGS_NUM); i++)
        tmp_regs.uregs[i] = va_arg(vl, uintptr_t);

    // push remaining parameters onto stack
    if (nargs > kREG_ARGS_NUM)
    {
        tmp_regs.sp -= sizeof(uintptr_t) * (nargs - kREG_ARGS_NUM);
        uintptr_t stack = tmp_regs.sp;
        for (int i = kREG_ARGS_NUM; i < nargs; ++i)
        {
            uintptr_t arg = va_arg(vl, uintptr_t);
            if (!_pMemOp->Write(stack, &arg, sizeof(uintptr_t)))
                return failure_return();
            stack += sizeof(uintptr_t);
        }
    }

    // Set return address
    tmp_regs.lr = callerAddress;

    // Set function address
    tmp_regs.pc = functionAddress;

    // Setup the current processor status register
    if (tmp_regs.pc & 1)
    {
        // thumb
        tmp_regs.pc &= (~1u);
        tmp_regs.cpsr |= CPSR_T_MASK;
    }
    else
    {
        // arm
        tmp_regs.cpsr &= ~CPSR_T_MASK;
    }

#elif defined(__i386__)

    // push all parameters onto stack
    tmp_regs.esp -= sizeof(uintptr_t) * nargs;
    uintptr_t stack = tmp_regs.esp;
    for (int i = 0; i < nargs; ++i)
    {
        uintptr_t arg = va_arg(vl, uintptr_t);
        if (!_pMemOp->Write(stack, &arg, sizeof(uintptr_t)))
            return failure_return();
        stack += sizeof(uintptr_t);
    }

    // Push return address onto stack
    tmp_regs.esp -= sizeof(uintptr_t);
    if (!_pMemOp->Write(tmp_regs.esp, &callerAddress, sizeof(uintptr_t)))
        return failure_return();

    // Set function address to call
    tmp_regs.eip = functionAddress;

#elif defined(__x86_64__)

    // Align, rsp - 8 must be a multiple of 16 at function entry point
    uintptr_t space = sizeof(uintptr_t);
    if (nargs > 6)
        space += sizeof(uintptr_t) * (nargs - 6);
    while (((tmp_regs.rsp - space - 8) & 0xF) != 0)
        tmp_regs.rsp--;

    // Fill [RDI, RSI, RDX, RCX, R8, R9] with the first 6 parameters
    for (int i = 0; (i < nargs) && (i < 6); ++i)
    {
        uintptr_t arg = va_arg(vl, uintptr_t);
        switch (i)
        {
        case 0:
            tmp_regs.rdi = arg;
            break;
        case 1:
            tmp_regs.rsi = arg;
            break;
        case 2:
            tmp_regs.rdx = arg;
            break;
        case 3:
            tmp_regs.rcx = arg;
            break;
        case 4:
            tmp_regs.r8 = arg;
            break;
        case 5:
            tmp_regs.r9 = arg;
            break;
        }
    }

    // Push remaining parameters onto stack
    if (nargs > 6)
    {
        tmp_regs.rsp -= sizeof(uintptr_t) * (nargs - 6);
        uintptr_t stack = tmp_regs.rsp;
        for (int i = 6; i < nargs; ++i)
        {
            uintptr_t arg = va_arg(vl, uintptr_t);
            if (!_pMemOp->Write(stack, &arg, sizeof(uintptr_t)))
                return failure_return();
            stack += sizeof(uintptr_t);
        }
    }

    // Push return address onto stack
    tmp_regs.rsp -= sizeof(uintptr_t);
    if (!_pMemOp->Write(tmp_regs.rsp, &callerAddress, sizeof(uintptr_t)))
        return failure_return();

    // Set function address to call
    tmp_regs.rip = functionAddress;

    // may be needed
    tmp_regs.rax = 0;
    tmp_regs.orig_rax = 0;

#else
#error "Unsupported ABI"
#endif

    // Set new registers and resume execution
    if (!setRegs(&tmp_regs) || !Cont())
        return failure_return();

    // Catch SIGSEGV or SIGILL caused by our code
    int status = 0;
    do {
        errno = 0;
        pid_t wp = Wait(&status, WUNTRACED);
        if (wp != remotePID())
        {
            KITTY_LOGE("callFunction: waitpid return %d. error=\"%s\".", wp, strerror(errno));
            return failure_return();
        }
        
        if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGILL))
            break;

        if (WIFEXITED(status))
        {
            KITTY_LOGE("callFunction: Target process exited (%d).", WEXITSTATUS(status));
            return 0;
        }

        if (WIFSIGNALED(status))
        {
            KITTY_LOGE("callFunction: Target process terminated (%d).", WTERMSIG(status));
            return 0;
        }

        if (!Cont()) return failure_return(); 
    } while (true);

    // Get current registers for return value
    if (!getRegs(&return_regs))
        return failure_return();

    uintptr_t result = kREGS_RET(return_regs);

    // Restore regs
    if (_autoRestoreRegs)
        setRegs(&backup_regs);

    KITTY_LOGD("callFunction: Calling function %p returned %p.", (void *)functionAddress, (void *)result);
    return result;
}