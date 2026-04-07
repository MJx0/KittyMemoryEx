#pragma once

#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <cerrno>
#include <functional>
#include <type_traits>

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

/**
 * @brief Enum for remote process call esults
 */
enum KT_RP_CALL_STATUS
{
    KT_RP_CALL_FAILED,
    KT_RP_CALL_SUCCESS,
    KT_RP_CALL_TIMEOUT,
    KT_RP_CALL_EXITED,
    KT_RP_CALL_CONT_FAILED,
    KT_RP_CALL_REGS_FAILED,
    KT_RP_CALL_WAIT_FAILED,
    KT_RP_CALL_MEM_FAILED,
    KT_RP_CALL_STEP_FAILED,
    KT_RP_CALL_NOT_STOPPED,
    KT_RP_CALL_MISMATCH_STOP,
};

/**
 * @brief Enum for hard break/watch point types
 */
enum KT_HW_BP_TYPE
{
    KT_HW_BP_EXECUTE = 0,
    KT_HW_BP_READ,
    KT_HW_BP_WRITE,
    KT_HW_BP_ACCESS
};

/**
 * @brief Enum for hard break/watch point sizes
 */
enum KT_HW_BP_SIZE
{
    KT_HW_BP_SIZE_EXEC = 0,
    KT_HW_BP_SIZE_1 = 1,
    KT_HW_BP_SIZE_2 = 2,
    KT_HW_BP_SIZE_3 = 3,
    KT_HW_BP_SIZE_4 = 4,
    KT_HW_BP_SIZE_5 = 5,
    KT_HW_BP_SIZE_6 = 6,
    KT_HW_BP_SIZE_7 = 7,
    KT_HW_BP_SIZE_8 = 8,
};

/**
 * @brief Enum for break/watch point results
 */
enum KT_BP_RESULT
{
    KT_BP_FAILED,
    KT_BP_SUCCESS,
    KT_BP_TIMEOUT,
    KT_BP_EXITED,
    KT_BP_CONT_FAILED,
    KT_BP_STEP_FAILED,
    KT_BP_REGS_FAILED,
    KT_BP_WAIT_FAILED,
    KT_BP_MEM_FAILED,
    KT_BP_NOT_STOPPED,
    KT_BP_MISMATCH_STOP,
};

/**
 * @brief Provides some asm instructions that are useful for KittyTrace class.
 */
namespace KittyTraceInsns
{
#if defined(__aarch64__)
    static constexpr int EXEC_SIZE = 4;
    static constexpr uint8_t BRKP[] = {0x00, 0x00, 0x20, 0xd4};
    static constexpr uint8_t SYSCALL[] = {0x01, 0x00, 0x00, 0xd4};
    static constexpr uint8_t NOP[] = {0x1f, 0x20, 0x03, 0xd5};
#elif defined(__arm__)
    static constexpr int THUMB_EXEC_SIZE = 2;
    static constexpr uint8_t THUMB_BRKP[] = {0x00, 0xbe};
    static constexpr uint8_t THUMB_SYSCALL[] = {0x00, 0xdf};
    static constexpr uint8_t THUMB_NOP[] = {0x00, 0xbf};

    static constexpr int EXEC_SIZE = 4;
    static constexpr uint8_t BRKP[] = {0x70, 0x00, 0x20, 0xe1};
    static constexpr uint8_t SYSCALL[] = {0x00, 0x00, 0x00, 0xef};
    static constexpr uint8_t NOP[] = {0x00, 0xf0, 0x20, 0xe3};
#elif defined(__x86_64__)
    static constexpr int EXEC_SIZE = 1;
    static constexpr uint8_t BRKP[] = {0xcc};
    static constexpr uint8_t SYSCALL[] = {0x0f, 0x05};
    static constexpr uint8_t NOP[] = {0x90};
#elif defined(__i386__)
    static constexpr int EXEC_SIZE = 1;
    static constexpr uint8_t BRKP[] = {0xcc};
    static constexpr uint8_t SYSCALL[] = {0xcd, 0x80};
    static constexpr uint8_t NOP[] = {0x90};
#endif
} // namespace KittyTraceInsns

#define KT_REGS_ALIGN_STACK(regs) regs.KT_REG_SP = uintptr_t(intptr_t(intptr_t(regs.KT_REG_SP) & intptr_t(~0xF)))
#define KT_REGS_ALIGN_STACK_N(regs, n)                                                                                 \
    regs.KT_REG_SP = uintptr_t(intptr_t((intptr_t(regs.KT_REG_SP) - intptr_t(n)) & intptr_t(~0xF)))

#define KT_ALIGN_STACK(s) s = uintptr_t(intptr_t(intptr_t(s) & intptr_t(~0xF)))
#define KT_ALIGN_STACK_N(s, n) s = uintptr_t(intptr_t((intptr_t(s) - intptr_t(n)) & intptr_t(~0xF)))

/**
 * @brief A structure to hold result data of a remote process function call.
 */
struct kitty_rp_call_t
{
    KT_RP_CALL_STATUS status = KT_RP_CALL_FAILED;
    union
    {
        intptr_t val = 0;
        uintptr_t ptr;
    } result;
};

/**
 * @brief A class for tracing and controlling the execution of processes in a debugging environment.
 */
class KittyTraceMgr
{
private:
    pid_t _pid;
    uintptr_t _defaultCaller;
    bool _attached, _seized, _autoRestoreRegs;
    int _remoteCallTimeout;

    kitty_rp_call_t _callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, int nargs, ...);
    kitty_rp_call_t _callSyscall(long sysnr, int nargs, ...);

public:
    KittyTraceMgr()
        : _pid(0), _defaultCaller(0), _attached(false), _seized(false), _autoRestoreRegs(true), _remoteCallTimeout(0)
    {
    }

    /**
     * @brief Constructs a new KittyTraceMgr object.
     *
     * @param pid The process ID to trace.
     * @param defaultCaller The default caller for remote function calls (optional).
     * @param autoRestoreRegs Whether to automatically restore registers on remote function calls (optional).
     * @param remoteCallTimeout The default remote call timeout (optional).
     */
    KittyTraceMgr(pid_t pid, uintptr_t defaultCaller = 0, bool autoRestoreRegs = true, int remoteCallTimeout = 0)
        : _pid(pid), _defaultCaller(defaultCaller), _attached(isAttached()), _seized(false),
          _autoRestoreRegs(autoRestoreRegs), _remoteCallTimeout(remoteCallTimeout)
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
     * @brief Stop all of traced process threads.
     * @return True if the stop was successful, false otherwise.
     */
    inline bool stopAllThreads()
    {
        return kill(_pid, SIGSTOP) != -1;
    }

    /**
     * @brief Continue all of the traced process threads.
     * @param sig Signal to send to the process (optional).
     * @return True if the continue was successful, false otherwise.
     */
    inline bool contAllThreads()
    {
        return kill(_pid, SIGCONT) != -1;
    }

    /**
     * @brief Stop the traced process thread.
     * @return True if the stop was successful, false otherwise.
     */
    bool stop();

    /**
     * @brief Continue the traced process thread.
     * @param sig Signal to send to the process (optional).
     * @return True if the continue was successful, false otherwise.
     */
    bool cont(int sig = 0);

    /**
     * @brief Wait for the process.
     * @param status Pointer to store the status of the process.
     * @param options waitpid options to use.
     * @param timeout_ms timeout in milliseconds (optional, default is 0)
     * @return The PID of the process.
     */
    pid_t wait(int *status, int options, int timeout_ms = 0) const;

    /**
     * @brief Wait for the process to enter or exit a syscall.
     * @return True if the wait was successful, false otherwise.
     */
    bool waitSyscall() const;

    /**
     * @brief Single-step the process.
     * @param steps Number of steps to single-step (default is 1).
     * @return True if the step was successful, false otherwise.
     */
    bool step(int steps = 1) const;

    /**
     * @brief Single-step and wait the process.
     * @param steps Number of steps to single-step (default is 1).
     * @return True if the step was successful, false otherwise.
     */
    bool waitStep(int steps = 1) const;

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
     * @brief Get the return address value from registers.
     * @param regs Pointer to the registers.
     * @return Value of the return address.
     */
    uintptr_t getReturnAddressFromRegs(user_regs_struct *regs)
    {
#if defined(__x86_64__) || defined(__i386__)
        uintptr_t ret = 0;
        peekMem(regs->KT_REG_SP, &ret, sizeof(uintptr_t));
        return ret;

#elif defined(__aarch64__) || defined(__arm__)
        return regs->KT_REG_LR;
#endif
    }

    /**
     * @brief Get the n-th argument value from registers.
     * @param regs Pointer to the registers.
     * @param arg_num  The zero-indexed argument number (0 for 1st arg, 1 for 2nd, etc.).
     * @return Value of the requested argument.
     *
     * @note T must be a numeric type.
     */
    template <typename T>
    T getArgFromRegs(user_regs_struct *regs, uint32_t arg_num)
    {
        static_assert(std::is_arithmetic<T>::value, "T must be a numeric type!");

#if defined(__x86_64__)
        switch (arg_num)
        {
        case 0:
            return regs->rdi;
        case 1:
            return regs->rsi;
        case 2:
            return regs->rdx;
        case 3:
            return regs->rcx;
        case 4:
            return regs->r8;
        case 5:
            return regs->r9;
        default:
            break;
        }

        uintptr_t arg = 0;
        peekMem(regs->KT_REG_SP + 8 + (arg_num - 6) * 8, &arg, sizeof(uintptr_t));
        return arg;

#elif defined(__i386__)
        uintptr_t arg = 0;
        peekMem(regs->KT_REG_SP + 4 + (arg_num * 4), &arg, sizeof(uintptr_t));
        return arg;

#elif defined(__aarch64__)
        if (arg_num < 8)
            return regs->regs[arg_num];

        uintptr_t arg = 0;
        peekMem(regs->KT_REG_SP + (arg_num - 8) * 8, &arg, sizeof(uintptr_t));
        return arg;

#elif defined(__arm__)
        if (arg_num < 4)
            return regs->uregs[arg_num];

        uintptr_t arg = 0;
        peekMem(regs->KT_REG_SP + (arg_num - 4) * 4, &arg, sizeof(uintptr_t));
        return arg;
#endif
    }

    /**
     * @brief Reads memory from a traced process using PTRACE_PEEKTEXT.
     * Works around ptrace's word-sized limitation by reading aligned
     * machine words and copying only the requested byte ranges.
     *
     * @param addr Remote address to read from.
     * @param buf Buffer to store the read data.
     * @param size Size of the data to read.
     *
     * @return Bytes read.
     */
    size_t peekMem(uintptr_t addr, void *buf, size_t size) const;

    /**
     * @brief Writes memory from a traced process using PTRACE_POKETEXT.
     * Works around ptrace's word-sized limitation by reading aligned
     * machine words and copying only the requested byte ranges.
     *
     * @param addr Remote address to write to.
     * @param buf Buffer containing the data to write.
     * @param size Size of the data to write.
     *
     * @return Bytes written.
     */
    size_t pokeMem(uintptr_t addr, const void *buf, size_t size) const;

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
     * @brief Returns the default timeout (ms) for remote function calls.
     */
    inline int remoteCallTimeout() const
    {
        return _remoteCallTimeout;
    }
    
    /**
     * @brief Sets the default remote function call timeout in milliseconds.
     * @param ms Timeout in milliseconds (0 or negaive to disable).
     */
    inline void setRemoteCallTimeout(int ms)
    {
        _remoteCallTimeout = ms > 0 ? ms : 0;
    }

    /**
     * @brief Call a function in the remote process and spoof return address.
     * @param callerAddress The address of the caller.
     * @param functionAddress The address of the function to call.
     * @param ... Arguments to pass to the function.
     * @return The address of the return value.
     */
    template <class... Args>
    kitty_rp_call_t callFunctionFrom(uintptr_t callerAddress, uintptr_t functionAddress, Args &&...a)
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
    kitty_rp_call_t callFunction(uintptr_t functionAddress, Args &&...a)
    {
        return _callFunctionFrom(_defaultCaller, functionAddress, sizeof...(a), std::forward<Args>(a)...);
    }

    /**
     * @brief Call a syscall in the remote process.
     * @note This function writes syscall + brkp instructions at PC/IP so PC/IP must be at valid executable address.
     * @param sysnr The syscall number.
     * @param ... Arguments to pass to the syscall.
     * @return The result of the syscall.
     */
    template <class... Args>
    kitty_rp_call_t callSyscall(long sysnr, Args &&...a)
    {
        return _callSyscall(sysnr, sizeof...(a), std::forward<Args>(a)...);
    }

    /**
     * @brief Sets and wait for software breakpoint at a given address.
     * @param address The address to set the breakpoint at.
     * @param cb Callback function to be executed when the breakpoint is hit.
     * @param timeout_ms timeout in milliseconds (0 or negative value, will disable timeout)
     * @return Value of KT_BP_RESULT enum.
     *
     * @note Breakpoint will be set into on traced thread.
     */
    KT_BP_RESULT setSoftBreakpointAndWait(uintptr_t address,
                                          const std::function<bool(user_regs_struct regs)> &cb,
                                          int timeout_ms);

    /**
     * @brief Sets and wait for hardware breakpoint at a given address.
     * @param address The address to set the breakpoint at.
     * @param type The type of hardware breakpoint (e.g., execute, read, write, access).
     * @param size The size of the data to watch (ignored if bp type is KT_HW_BP_EXECUTE).
     * @param slot The slot number for the breakpoint.
     * @param cb Callback function to be executed when the breakpoint is hit.
     * @param timeout_ms Timeout in milliseconds (0 or negative value, will disable timeout)
     * @return Value of KT_BP_RESULT enum.
     *
     * @note Breakpoint will be set into slot 0 on traced thread.
     */
    KT_BP_RESULT setHardBreakpointAndWait(uintptr_t address,
                                          KT_HW_BP_TYPE type,
                                          KT_HW_BP_SIZE size,
                                          int slot,
                                          const std::function<bool(user_regs_struct regs)> &cb,
                                          int timeout_ms);

    /**
     * @brief Sets a hardware breakpoint on a specified address for traced thread.
     *
     * @param address The address to set the breakpoint at.
     * @param type The type of hardware breakpoint (e.g., execute, read, write, access).
     * @param size The size of the data to watch (ignored if bp type is KT_HW_BP_EXECUTE).
     * @param slot The slot number for the breakpoint.
     * @return True if the breakpoint was successfully set, false otherwise.
     */
    bool setHwBreakpoint(uintptr_t address, KT_HW_BP_TYPE type, KT_HW_BP_SIZE size, int slot);

    /**
     * @brief Clears a hardware breakpoint on a specified address for traced thread.
     *
     * @param type The type of hardware breakpoint (e.g., execute, read, write, access).
     * @param slot The slot number for the breakpoint.
     * @return True if the breakpoint was successfully cleared, false otherwise.
     */
    bool clearHwBreakpoint(KT_HW_BP_TYPE type, int slot);
};
