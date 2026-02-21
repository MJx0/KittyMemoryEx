#pragma once

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <atomic>
#include <vector>
#include <functional>
#include <cstdint>
#include <cstring>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

static constexpr size_t KT_WATCH_PAGES = 8;

enum KT_WATCH_LEN
{
    KT_PERFWATCH_LEN_1 = 1,
    KT_PERFWATCH_LEN_2 = 2,
    KT_PERFWATCH_LEN_3 = 3,
    KT_PERFWATCH_LEN_4 = 4,
    KT_PERFWATCH_LEN_5 = 5,
    KT_PERFWATCH_LEN_6 = 6,
    KT_PERFWATCH_LEN_7 = 7,
    KT_PERFWATCH_LEN_8 = 8,
};

enum KT_WATCH_TYPE
{
    KT_PERFWATCH_EMPTY = 0,
    KT_PERFWATCH_R = 1,
    KT_PERFWATCH_W = 2,
    KT_PERFWATCH_RW = KT_PERFWATCH_R | KT_PERFWATCH_W,
    KT_PERFWATCH_X = 4,
    KT_PERFWATCH_INVALID = KT_PERFWATCH_RW | KT_PERFWATCH_X,
};

struct KittyPerfSample
{
    uint64_t ip;
    uint32_t pid;
    uint32_t tid;
    uint64_t time;
    uint64_t addr;

    KittyPerfSample() : ip(0), pid(0), tid(0), time(0), addr(0)
    {
    }
    KittyPerfSample(uint64_t ip, uint32_t pid, uint32_t tid, uint64_t time, uint64_t addr)
        : ip(ip), pid(pid), tid(tid), time(time), addr(addr)
    {
    }
};

class KittyPerfWatch
{

public:
    KittyPerfWatch() = default;
    ~KittyPerfWatch()
    {
        clear();
    }

    bool add(pid_t tid, uintptr_t addr, KT_WATCH_TYPE bp_type, KT_WATCH_LEN bp_len);
    void poll(int timeout_ms, const std::function<bool(const KittyPerfSample &)> &cb);
    void clear();

protected:
    struct WatchInfo
    {
        int fd = -1;
        void *mmap = nullptr;
        size_t mmap_sz = 0;
    };

    std::vector<WatchInfo> _watches;

    static inline int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd,
                                      unsigned long flags)
    {
#if defined(__aarch64__)
        return syscall(241, attr, pid, cpu, group_fd, flags);
#elif defined(__arm__)
        return syscall(364, attr, pid, cpu, group_fd, flags);
#elif defined(__i386__)
        return syscall(336, attr, pid, cpu, group_fd, flags);
#elif defined(__x86_64__)
        return syscall(298, attr, pid, cpu, group_fd, flags);
#else
#error "Unsupported ABI"
#endif
    }

    bool enable();
    bool disable();
    void consumeRecord(const WatchInfo &w, KittyPerfSample *out);
    void pollOnce(int timeout_ms, KittyPerfSample *out);
};

class KittyPerfTrap : public KittyPerfWatch
{
public:
    bool add(pid_t tid, uintptr_t addr, KT_WATCH_TYPE bp_type, KT_WATCH_LEN bp_len);
};
