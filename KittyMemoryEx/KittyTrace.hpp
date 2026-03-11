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

/**
 * @brief A class for tracing and controlling the execution of processes in a debugging environment.
 */
class KittyTraceMgr
{
private:
    pid_t _pid;
    uintptr_t _defaultCaller;
    bool _attached, _autoRestoreRegs;

    uintptr_t _callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, int nargs, ...);
    intptr_t _callSyscall(long sysnr, int nargs, ...);

public:
    KittyTraceMgr() : _pid(0), _defaultCaller(0), _attached(false), _autoRestoreRegs(true)
    {
    }

    /**
     * @brief Constructs a new KittyTraceMgr object.
     *
     * @param pid The process ID to trace.
     * @param defaultCaller The default caller for remote function calls (optional).
     * @param autoRestoreRegs Whether to automatically restore registers on remote function calls (optional).
     */
    KittyTraceMgr(pid_t pid, uintptr_t defaultCaller = 0, bool autoRestoreRegs = true)
        : _pid(pid), _defaultCaller(defaultCaller), _attached(isAttached()), _autoRestoreRegs(autoRestoreRegs)
    {
    }

    /**
     * @brief Returns the PID of the process being traced.
     */
    inline pid_t pid() const
    {
        return _pid;
    }

    /**
     * @brief Check if the process is currently attached.
     */
    inline bool isAttached() const
    {
        KittyMemoryEx::ProcStatus pstatus{};
        KittyMemoryEx::ProcStatus::parse(_pid, &pstatus);
        int tracerPID = pstatus.getInt("TracerPid");
        return _pid >= 0 && getpid() == tracerPID;
    }

    /**
     * @brief Get a list of all threads in the traced process.
     * @return A vector of thread IDs.
     */
    inline std::vector<pid_t> threads() const
    {
        return KittyMemoryEx::getAllThreads(_pid);
    }

    /**
     * @brief Attach to the process.
     * @param options PTRACE options to use (optional).
     * @return True if the attach was successful, false otherwise.
     */
    bool attach(int options = 0);

    /**
     * @brief Seize the process.
     * @param options PTRACE options to use (optional).
     * @return True if the seize was successful, false otherwise.
     */
    bool seize(int options = 0);

    /**
     * @brief Set options for the process being traced.
     * @param options PTRACE options to set.
     * @return True if the options were set successfully, false otherwise.
     */
    bool setOptions(int options);

    /**
     * @brief Detach from the process.
     * @return True if the detach was successful, false otherwise.
     */
    bool detach();

    /**
     * @brief Interrupt the process.
     * @return True if the interrupt was successful, false otherwise.
     */
    bool interrupt();

    /**
     * @brief Continue the process.
     * @param sig Signal to send to the process (optional).
     * @return True if the continue was successful, false otherwise.
     */
    bool cont(int sig = 0);

    /**
     * @brief Wait for the process.
     * @param status Pointer to store the status of the process.
     * @param options waitpid options to use.
     * @return The PID of the process.
     */
    inline pid_t wait(int *status, int options) const
    {
        return _attached ? waitpid(_pid, status, options) : -1;
    }

    /**
     * @brief Wait for the process to enter or exit a syscall.
     * @return True if the wait was successful, false otherwise.
     */
    bool waitSyscall() const;

    /**
     * @brief Single-step the process.
     * @param steps Number of steps to single-step.
     * @return True if the step was successful, false otherwise.
     */
    bool step(int steps = 1) const;

    /**
     * @brief Get the signal information of the process.
     * @param si Pointer to store the signal information.
     * @return True if the signal information was retrieved successfully, false otherwise.
     */
    inline bool getSignalInfo(siginfo_t *si) const
    {
        if (!si || !_pid || !_attached)
            return false;
        return ptrace(PTRACE_GETSIGINFO, _pid, 0, si) == 0;
    }

    /**
     * @brief Get the current registers of the process.
     * @param regs Pointer to store the registers.
     * @return True if the registers were retrieved successfully, false otherwise.
     */
    bool getRegs(user_regs_struct *regs) const;

    /**
     * @brief Set the current registers of the process.
     * @param regs Pointer to the registers to set.
     * @return True if the registers were set successfully, false otherwise.
     */
    bool setRegs(user_regs_struct *regs) const;

    /**
     * @brief Read memory from the remote process.
     * @param addr Address to read from.
     * @param buf Buffer to store the read data.
     * @param size Size of the data to read.
     * @return True if the read was successful, false otherwise.
     */
    bool peekMem(uintptr_t addr, void *buf, size_t size) const;

    /**
     * @brief Write memory to the remote process.
     * @param addr Address to write to.
     * @param buf Buffer containing the data to write.
     * @param size Size of the data to write.
     * @return True if the write was successful, false otherwise.
     */
    bool pokeMem(uintptr_t addr, const void *buf, size_t size) const;

    /**
     * @brief Returns the default caller address for remote function calls.
     */
    inline uintptr_t defaultCaller() const
    {
        return _defaultCaller;
    }

    /**
     * @brief Sets the default caller address for remote function calls.
     * @param caller The default caller address.
     */
    inline void setDefaultCaller(uintptr_t caller)
    {
        _defaultCaller = caller;
    }

    /**
     * @brief Returns true if automatic registers restore for remote function calls is enabled, false otherwise.
     */
    inline bool autoRestoreRegs() const
    {
        return _autoRestoreRegs;
    }

    /**
     * @brief Sets the automatic registers restore flag for remote function calls.
     * @param flag True to enable automatic restore, false otherwise.
     */
    inline void setAutoRestoreRegs(bool flag)
    {
        _autoRestoreRegs = flag;
    }

    /**
     * @brief Call a function in the remote process and spoof return address.
     * @param callerAddress The address of the caller.
     * @param functionAddress The address of the function to call.
     * @param ... Arguments to pass to the function.
     * @return The address of the return value.
     */
    template <class... Args>
    uintptr_t callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, Args &&...a)
    {
        return _callFunctionFrom(callerAddress, functionAddress, sizeof...(a), std::forward<Args>(a)...);
    }

    /**
     * @brief Call a function in the remote process.
     * @param functionAddress The address of the function to call.
     * @param ... Arguments to pass to the function.
     * @return The address of the return value.
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
    /**
     * @brief Call a syscall in the remote process.
     * @note This function writes syscall + brkp instructions at PC/IP so PC/IP must be at valid executable address.
     * @param sysnr The syscall number.
     * @param ... Arguments to pass to the syscall.
     * @return The result of the syscall.
     */
    template <class... Args>
    intptr_t callSyscall(long sysnr, Args &&...a)
    {
        return _callSyscall(sysnr, sizeof...(a), std::forward<Args>(a)...);
    }

    /**
     * @brief Sets and wait for software breakpoint at a given address.
     * @param address The address to set the breakpoint at.
     * @param cb Callback function to be executed when the breakpoint is hit.
     * @return True if the breakpoint was set and triggered successfully, false otherwise.
     */
    bool softTrapWait(uintptr_t address, const std::function<bool(user_regs_struct regs)> &cb);

#if 0
     /**
     * @brief Sets and wait for hardware breakpoint at a given address.
     * @param address The address to set the breakpoint at.
     * @param cb Callback function to be executed when the breakpoint is hit.
     * @return True if the breakpoint was set and triggered successfully, false otherwise.
     */
    bool hardTrapWait(uintptr_t address, size_t size, KT_TRAP_TYPE type,
                    const std::function<bool(user_regs_struct regs)> &cb);
#endif
};
