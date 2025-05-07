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
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(__aarch64__)
#define pt_regs user_regs_struct
#endif

#if defined(__i386__)
#define kREGS_RET(regs) regs.eax
#define kREGS_PC(regs) regs.eip

#elif defined(__x86_64__)
#define kREGS_RET(regs) regs.rax
#define kREGS_PC(regs) regs.rip

#elif defined(__aarch64__) || defined(__arm__)
#define kREGS_RET(regs) regs.r0
#define kREGS_PC(regs) regs.pc
#endif

class KittyTraceMgr
{
private:
    IKittyMemOp *_pMemOp;
    uintptr_t _defaultCaller;
    bool _autoRestoreRegs;

public:
    KittyTraceMgr() : _pMemOp(nullptr), _defaultCaller(0), _autoRestoreRegs(true) {}
    KittyTraceMgr(IKittyMemOp *pMemOp, uintptr_t defaultCaller = 0, bool autoRestoreRegs = true)
        : _pMemOp(pMemOp), _defaultCaller(defaultCaller), _autoRestoreRegs(autoRestoreRegs) {}

    inline pid_t remotePID() const { return _pMemOp ? _pMemOp->processID() : 0; }

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
        return _pMemOp->processID() > 0 ? waitpid(remotePID(), status, options) : 0;
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
     * Default caller to use in callFunction
     */
    inline uintptr_t defaultCaller() const { return _defaultCaller; }

    /**
     * Set a default caller to use in callFunction
     */
    inline void setDefaultCaller(uintptr_t caller) { _defaultCaller = caller; }

    /**
     * Automatically back up and restore regs after a remote function call
     */
    inline bool autoRestoreRegs() const { return _autoRestoreRegs; }

    /**
     * Set to automatically back up and restore regs after a remote function call
     */
    inline void setAutoRestoreRegs(bool flag) { _autoRestoreRegs = flag; }

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