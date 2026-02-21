#pragma once

#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <cerrno>
#include <functional>

#include "KittyUtils.hpp"
#include "KittyMemoryEx.hpp"

#if defined(__LP64__)
#define KT_PTRACE_GETREG_REQ PTRACE_GETREGSET
#define KT_PTRACE_SETREG_REQ PTRACE_SETREGSET
#else
#define KT_PTRACE_GETREG_REQ PTRACE_GETREGS
#define KT_PTRACE_SETREG_REQ PTRACE_SETREGS
#endif

#if defined(__arm__)
#define user_regs_struct user_regs
#endif

#if defined(__aarch64__) || defined(__arm__)
#define KT_CPSR_T_MASK (1u << 5)
#endif

#if defined(__i386__)
#define KT_REG_RET eax
#define KT_REG_PC eip
#define KT_REG_IP eip
#define KT_REG_SP esp
#define KT_REG_SYSNR eax
#define KT_REG_ARGS_NUM 0

#elif defined(__x86_64__)
#define KT_REG_RET rax
#define KT_REG_PC rip
#define KT_REG_IP rip
#define KT_REG_SP rsp
#define KT_REG_SYSNR rax
#define KT_REG_ARGS_NUM 6

#elif defined(__aarch64__)
#define KT_REG_RET regs[0]
#define KT_REG_PC pc
#define KT_REG_IP pc
#define KT_REG_SP sp
#define KT_REG_SYSNR regs[8]
#define KT_REG_LR regs[30]
#define KT_REG_CPSR pstate
#define KT_REG_ARGS_NUM 8

#elif defined(__arm__)
#define KT_REG_RET uregs[0]
#define KT_REG_PC uregs[15]
#define KT_REG_IP uregs[15]
#define KT_REG_SP uregs[13]
#define KT_REG_SYSNR uregs[7]
#define KT_REG_LR uregs[14]
#define KT_REG_CPSR uregs[16]
#define KT_REG_ARGS_NUM 4

#endif

enum KT_TRAP_TYPE
{
    KT_TRAP_EXECUTE = 0,
    KT_TRAP_READ,
    KT_TRAP_WRITE,
    KT_TRAP_ACCESS
};

namespace KittyTraceInsns
{
#if defined(__aarch64__)
    static constexpr uint8_t brkTrapInsn[] = {0x00, 0x00, 0x20, 0xd4};
    static constexpr uint8_t syscallInsn[] = {0x01, 0x00, 0x00, 0xd4};
    static constexpr uint8_t nopInsn[] = {0x1f, 0x20, 0x03, 0xd5};
#elif defined(__arm__)
    static constexpr uint8_t brkTrapInsn[] = {0x70, 0x00, 0x20, 0xe1};
    static constexpr uint8_t syscallInsn[] = {0x00, 0x00, 0x00, 0xef};
    static constexpr uint8_t nopInsn[] = {0x00, 0xf0, 0x20, 0xe3};
#elif defined(__x86_64__)
    static constexpr uint8_t brkTrapInsn[] = {0xcc};
    static constexpr uint8_t syscallInsn[] = {0x0f, 0x05};
    static constexpr uint8_t nopInsn[] = {0x90};
#elif defined(__i386__)
    static constexpr uint8_t brkTrapInsn[] = {0xcc};
    static constexpr uint8_t syscallInsn[] = {0xcd, 0x80};
    static constexpr uint8_t nopInsn[] = {0x90};
#endif
} // namespace KittyTraceInsns

#define KT_REGS_ALIGN_STACK(regs) regs.KT_REG_SP = uintptr_t(intptr_t(intptr_t(regs.KT_REG_SP) & intptr_t(~0xF)))
#define KT_REGS_ALIGN_STACK_N(regs, n)                                                                                 \
    regs.KT_REG_SP = uintptr_t(intptr_t((intptr_t(regs.KT_REG_SP) - intptr_t(n)) & intptr_t(~0xF)))

#define KT_ALIGN_STACK(s) s = uintptr_t(intptr_t(intptr_t(s) & intptr_t(~0xF)))
#define KT_ALIGN_STACK_N(s, n) s = uintptr_t(intptr_t((intptr_t(s) - intptr_t(n)) & intptr_t(~0xF)))

class KittyTraceMgr
{
private:
    pid_t _pid;
    uintptr_t _defaultCaller;
    bool _attached, _autoRestoreRegs;

    /**
     * Call remote function and spoof return address
     */
    uintptr_t _callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, int nargs, ...);

    /**
     * Call remote syscall
     */
    intptr_t _callSyscall(long sysnr, int nargs, ...);

public:
    KittyTraceMgr() : _pid(0), _defaultCaller(0), _attached(false), _autoRestoreRegs(true)
    {
    }
    KittyTraceMgr(pid_t pid, uintptr_t defaultCaller = 0, bool autoRestoreRegs = true)
        : _pid(pid), _defaultCaller(defaultCaller), _attached(isAttached()), _autoRestoreRegs(autoRestoreRegs)
    {
    }

    inline pid_t pid() const
    {
        return _pid;
    }

    inline bool isAttached() const
    {
        int tracer = 0;
        return _pid >= 0 && KittyMemoryEx::ProcStatus::getIntFast(_pid, "TracerPid", &tracer) && getpid() == tracer;
    }

    inline std::vector<pid_t> threads() const
    {
        return KittyMemoryEx::getAllThreads(_pid);
    }

    /**
     * PTRACE_ATTACH
     */
    bool attach(int options = 0);

    /**
     * PTRACE_SEIZE
     */
    bool seize(int options = 0);

    /**
     * PTRACE_SETOPTIONS
     */
    bool setOptions(int options);

    /**
     * PTRACE_DETACH
     */
    bool detach();

    /**
     * PTRACE_INTERRUPT
     */
    bool interrupt();

    /**
     * PTRACE_CONT
     */
    bool cont(int sig = 0);

    /**
     * waitpid(pid)
     */
    inline pid_t wait(int *status, int options) const
    {
        return _attached ? waitpid(_pid, status, options) : -1;
    }

    /**
     * PTRACE_SYSCALL
     */
    bool waitSyscall() const;

    /**
     * PTRACE_SINGLESTEP
     */
    bool step(int steps = 1) const;

    /**
     * PTRACE_GETSIGINFO
     */
    inline bool getSignalInfo(siginfo_t *si) const
    {
        if (!si || !_pid || !_attached)
            return false;
        return ptrace(PTRACE_GETSIGINFO, _pid, 0, si) == 0;
    }

    /**
     * PTRACE_GETREG / PTRACE_GETREGSET
     */
    bool getRegs(user_regs_struct *regs) const;

    /**
     * PTRACE_SETREG / PTRACE_SETREGSET
     */
    bool setRegs(user_regs_struct *regs) const;

    /**
     * Read remote process memory
     */
    bool peekMem(uintptr_t addr, void *buf, size_t size) const;

    /**
     * Write remote process memory
     */
    bool pokeMem(uintptr_t addr, const void *buf, size_t size) const;

    /**
     * Default caller to use in callFunction
     */
    inline uintptr_t defaultCaller() const
    {
        return _defaultCaller;
    }

    /**
     * Set a default caller to use in callFunction
     */
    inline void setDefaultCaller(uintptr_t caller)
    {
        _defaultCaller = caller;
    }

    /**
     * Automatically back up and restore regs after a remote function call
     */
    inline bool autoRestoreRegs() const
    {
        return _autoRestoreRegs;
    }

    /**
     * Set to automatically back up and restore regs after a remote function call
     */
    inline void setAutoRestoreRegs(bool flag)
    {
        _autoRestoreRegs = flag;
    }

    /**
     * Call remote function and spoof return address
     */
    template <class... Args>
    uintptr_t callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, Args &&...a)
    {
        return _callFunctionFrom(callerAddress, functionAddress, sizeof...(a), std::forward<Args>(a)...);
    }

    /**
     * Call remote function
     */
    template <class... Args>
    uintptr_t callFunction(uintptr_t functionAddress, Args &&...a)
    {
        return _callFunctionFrom(_defaultCaller, functionAddress, sizeof...(a), std::forward<Args>(a)...);
    }

    /**
     * Call remote syscall
     * Write syscall + brkp at PC (PC MUST BE VALID)
     */
    template <class... Args>
    intptr_t callSyscall(long sysnr, Args &&...a)
    {
        return _callSyscall(sysnr, sizeof...(a), std::forward<Args>(a)...);
    }

    /**
     * Software breakpoint
     */
    bool softTrapWait(uintptr_t address, const std::function<bool(user_regs_struct regs)> &cb);

#if 0
     /**
     * Hardware breakpoint
     * Size must be 1 ~ 8
     */
    bool hardTrapWait(uintptr_t address, size_t size, KT_TRAP_TYPE type,
                    const std::function<bool(user_regs_struct regs)> &cb);
#endif
};
