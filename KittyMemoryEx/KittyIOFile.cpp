#include "KittyIOFile.hpp"

bool KittyIOFile::Open()
{
    if (_fd <= 0)
    {
        errno = 0, _error = 0;
        if (_mode)
            _fd = open(_filePath.c_str(), _flags, _mode);
        else
            _fd = open(_filePath.c_str(), _flags);

        _error = _fd > 0 ? 0 : errno;
    }
    return _fd > 0;
}

bool KittyIOFile::Close()
{
    bool rt = true;
    if (_fd > 0)
    {
        errno = 0, _error = 0;
        rt = close(_fd) != -1;
        if (!rt)
            _error = errno;

        _fd = 0;
    }
    return rt;
}

ssize_t KittyIOFile::Read(uintptr_t offset, void *buffer, size_t len)
{
    return KT_EINTR_RETRY(pread64(_fd, buffer, len, offset));
}

ssize_t KittyIOFile::Write(uintptr_t offset, const void *buffer, size_t len)
{
    return KT_EINTR_RETRY(pwrite64(_fd, buffer, len, offset));
}

struct stat64 KittyIOFile::Stat()
{
    errno = 0, _error = 0;
    struct stat64 s;
    if (stat64(_filePath.c_str(), &s) == -1)
        _error = errno;
    return s;
}

std::vector<char> KittyIOFile::toBuffer()
{
    std::vector<char> buf;

    const size_t len = Stat().st_size;
    if (!len)
        return buf;

    buf.resize(len);
    memset(&buf[0], 0, len);

    Read(0, &buf[0], len);
    return buf;
}

bool KittyIOFile::writeToFile(const std::string &filePath)
{
    auto buf = toBuffer();
    if (buf.empty())
        return false;

    KittyIOFile f(filePath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    return f.Open() && size_t(f.Write(0, buf.data(), buf.size())) == buf.size();
}

bool KittyIOFile::writeToFd(int fd)
{
    if (fd <= 0)
        return false;

    auto buf = toBuffer();
    if (buf.empty())
        return false;

    char *ptr = buf.data();
    ssize_t len = buf.size();

    do
    {
        ssize_t nwritten = KT_EINTR_RETRY(write(fd, ptr, len));
        if (nwritten <= 0)
        {
            _error = errno;
            return false;
        }

        ptr += nwritten;
        len -= nwritten;
    } while (len > 0);

    return true;
}