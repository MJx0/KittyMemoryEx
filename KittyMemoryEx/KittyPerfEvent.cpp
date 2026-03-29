#include "KittyPerfEvent.hpp"

bool KittyPerfWatch::add(pid_t tid, uintptr_t addr, KT_WATCH_TYPE bp_type, KT_WATCH_LEN bp_len)
{
#if defined(__arm__) || defined(__aarch64__)
    addr &= ~3UL;
#endif

    perf_event_attr pe{};
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.config = 0;
    pe.size = sizeof(pe);

    pe.bp_addr = addr;
    pe.bp_len = bp_len;
    pe.bp_type = bp_type;

    pe.sample_period = 1;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR;

    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.disabled = 1;
    pe.wakeup_events = 1;
    pe.precise_ip = 2;

    int fd = perf_event_open(&pe, tid, -1, -1, 0);
    if (fd < 0)
        return false;

    size_t page_sz = sysconf(_SC_PAGESIZE);
    size_t mmap_sz = (1 + KT_WATCH_PAGES) * page_sz;

    void *base = mmap(nullptr, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!base || base == MAP_FAILED)
    {
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        close(fd);
        return false;
    }

    auto *meta = reinterpret_cast<perf_event_mmap_page *>(base);
    if (meta->data_size == 0)
    {
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        munmap(base, mmap_sz);
        close(fd);
        return false;
    }

    WatchInfo w{};
    w.fd = fd;
    w.mmap = base;
    w.mmap_sz = mmap_sz;

    _watches.push_back(w);

    return true;
}

bool KittyPerfTrap::add(pid_t tid, uintptr_t addr, KT_WATCH_TYPE bp_type, KT_WATCH_LEN bp_len)
{
    size_t n = _watches.size();
    if (KittyPerfWatch::add(tid, addr, bp_type, bp_len) && ++n == _watches.size())
    {
        int fd = _watches.front().fd;
        fcntl(fd, F_SETOWN, tid);     // set owner thread to receive signals
        fcntl(fd, F_SETSIG, SIGTRAP); // signal type
        fcntl(fd, F_SETFL, O_ASYNC);  // enable async notification
        return true;
    }
    return false;
}

bool KittyPerfWatch::enable()
{
    for (auto &w : _watches)
    {
        if (w.fd >= 0)
        {
            ioctl(w.fd, PERF_EVENT_IOC_RESET, 0);
            if (ioctl(w.fd, PERF_EVENT_IOC_ENABLE, 0) < 0)
                return false;
        }
    }
    return true;
}

bool KittyPerfWatch::disable()
{
    for (auto &w : _watches)
    {
        if (w.fd >= 0)
        {
            ioctl(w.fd, PERF_EVENT_IOC_RESET, 0);
            if (ioctl(w.fd, PERF_EVENT_IOC_DISABLE, 0) < 0)
                return false;
        }
    }
    return true;
}

void KittyPerfWatch::clear()
{
    for (auto &w : _watches)
    {
        if (w.fd >= 0)
        {
            ioctl(w.fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(w.fd, PERF_EVENT_IOC_DISABLE, 0);
        }

        if (w.mmap && w.mmap != MAP_FAILED && w.mmap_sz)
            munmap(w.mmap, w.mmap_sz);

        if (w.fd >= 0)
            close(w.fd);

        w = {};
    }

    _watches.clear();
}

void KittyPerfWatch::consumeRecord(const WatchInfo &w, KittyPerfSample *out)
{
    if (w.mmap == nullptr || w.mmap == MAP_FAILED || w.mmap_sz == 0)
        return;

    auto *meta = reinterpret_cast<perf_event_mmap_page *>(w.mmap);

    char *data = reinterpret_cast<char *>(w.mmap) + meta->data_offset;
    const uint64_t data_size = meta->data_size;
    const uint64_t mask = data_size - 1;

    uint64_t head = meta->data_head;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    uint64_t tail = meta->data_tail;

    while (tail < head)
    {
        uint64_t offset = tail & mask;

        perf_event_header hdr = {};
        if (offset + sizeof(hdr) <= data_size)
        {
            memcpy(&hdr, data + offset, sizeof(hdr));
        }
        else
        {
            size_t first = data_size - offset;
            memcpy(&hdr, data + offset, first);
            memcpy(reinterpret_cast<char *>(&hdr) + first, data, sizeof(hdr) - first);
        }

        if (hdr.size < sizeof(perf_event_header))
            break;

        if (tail + hdr.size > head)
            break;

        if (out && hdr.type == PERF_RECORD_SAMPLE)
        {
            const size_t payload_size = hdr.size - sizeof(hdr);
            const uint64_t payload_offset = (offset + sizeof(hdr)) & mask;

            if (payload_size >= sizeof(KittyPerfSample))
            {
                if (payload_offset + sizeof(KittyPerfSample) <= data_size)
                {
                    memcpy(out, data + payload_offset, sizeof(KittyPerfSample));
                }
                else
                {
                    size_t first = data_size - payload_offset;
                    memcpy(out, data + payload_offset, first);
                    memcpy(reinterpret_cast<char *>(out) + first, data, sizeof(KittyPerfSample) - first);
                }
            }
        }

        tail += hdr.size;
    }

    __atomic_thread_fence(__ATOMIC_RELEASE);
    meta->data_tail = tail;
}

void KittyPerfWatch::pollOnce(int timeout_ms, KittyPerfSample *out)
{
    if (_watches.empty())
        return;

    std::vector<pollfd> pfds;
    pfds.reserve(_watches.size());

    for (auto &w : _watches)
        pfds.push_back({w.fd, POLLIN, 0});

    int ret = ::poll(pfds.data(), pfds.size(), timeout_ms);
    if (ret <= 0)
        return;

    for (size_t i = 0; i < pfds.size(); ++i)
    {
        if (pfds[i].revents & POLLIN)
        {
            consumeRecord(_watches[i], out);
        }
    }
}

void KittyPerfWatch::poll(int timeout_ms, const std::function<bool(const KittyPerfSample &)> &cb)
{
    if (!cb || !enable())
        return;

    while (true)
    {
        KittyPerfSample out{};
        pollOnce(timeout_ms, &out);
        if (cb(out))
            break;
    }

    disable();
}
