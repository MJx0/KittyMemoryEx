#pragma once

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "KittyUtils.hpp"
#include "KittyMemoryEx.hpp"
#include "KittyMemOp.hpp"

#if defined(__LP64__)
#define PTRACE_GETREG_REQ PTRACE_GETREGSET
#define PTRACE_SETREG_REQ PTRACE_SETREGSET
#else
#define PTRACE_GETREG_REQ PTRACE_GETREGS
#define PTRACE_SETREG_REQ PTRACE_SETREGS
#endif

#if defined(__aarch64__) || defined(__arm__)
#define CPSR_T_MASK (1u << 5)
#define REGS_RETURN_VALUE(regs) regs.r0
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(__aarch64__)
#define pt_regs user_regs_struct
#endif

#if defined(__aarch64__)
#define REG_ARGS_NUM 8

#define uregs regs
#define r0 regs[0]
#define lr regs[30]
#define cpsr pstate

#elif defined(__arm__)
#define REG_ARGS_NUM 4

#define sp ARM_sp
#define pc ARM_pc
#define r0 ARM_r0
#define lr ARM_lr
#define cpsr ARM_cpsr

#elif defined(__i386__)
#define REGS_RETURN_VALUE(regs) regs.eax

#elif defined(__x86_64__)
#define REGS_RETURN_VALUE(regs) regs.rax
#endif

class KittyTraceMgr
{
private:
    IKittyMemOp *_pMemOp;
    uintptr_t _defaultCaller;

public:
    KittyTraceMgr() : _pMemOp(nullptr), _defaultCaller(0) {}
    KittyTraceMgr(IKittyMemOp *pMemOp, uintptr_t defaultCaller = 0) : _pMemOp(pMemOp), _defaultCaller(defaultCaller) {}

    inline pid_t remotePID() const { return _pMemOp ? _pMemOp->remotePID() : 0; }

    inline bool isAttached() const
    {
        return getpid() == KittyMemoryEx::getStatusInteger(remotePID(), "TracerPid");
    }

    /**
     * PTRACE_ATTACH
     */
    bool Attach() const;

    /**
     * PTRACE_DETACH
     */
    bool Detach() const;

    /**
     * PTRACE_CONT
     */
    bool Cont() const;

    /**
     * waitpid wrapper
     */
    inline pid_t Wait(int *status, int options) const
    {
        return _pMemOp->remotePID() > 0 ? waitpid(remotePID(), status, options) : 0;
    }

    /**
     * PTRACE_GETREG / PTRACE_GETREGSET
     */
    bool getRegs(pt_regs *regs) const;

    /**
     * PTRACE_SETREG / PTRACE_SETREGSET
     */
    bool setRegs(pt_regs *regs) const;

    /**
     * Call remote function and spoof return address
     */
    uintptr_t callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, int nargs, ...) const;

    /**
     * Call remote function
     */
    template <class... Args>
    uintptr_t callFunction(uintptr_t functionAddress, int nargs, Args &&...a) const
    {
        return callFunctionFrom(_defaultCaller, functionAddress, nargs, std::forward<Args>(a)...);
    }
};