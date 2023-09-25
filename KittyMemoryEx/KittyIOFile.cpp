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
    char *buf = (char *)buffer;
    size_t bytesRead = 0;
    do
    {
        errno = 0, _error = 0;
#ifdef __LP64__
        ssize_t readSize = pread64(_fd, buf + bytesRead, len - bytesRead, (int64_t)offset + bytesRead);
#else
        ssize_t readSize = pread(_fd, buf + bytesRead, len - bytesRead, (int32_t)offset + bytesRead);
#endif
        if (readSize <= 0)
        {
            _error = errno;
            return bytesRead > 0 ? bytesRead : readSize;
        }

        bytesRead += readSize;
    } while (bytesRead < len);
    return bytesRead;
}

ssize_t KittyIOFile::Write(uintptr_t offset, const void *buffer, size_t len)
{
    const char *buf = (const char *)buffer;
    size_t bytesWritten = 0;
    do
    {
        errno = 0, _error = 0;
#ifdef __LP64__
        ssize_t writeSize = pwrite64(_fd, buf + bytesWritten, len - bytesWritten, (int64_t)offset + bytesWritten);
#else
        ssize_t writeSize = pwrite(_fd, buf + bytesWritten, len - bytesWritten, (int32_t)offset + bytesWritten);
#endif
        if (writeSize <= 0)
        {
            _error = errno;
            return bytesWritten > 0 ? bytesWritten : writeSize;
        }

        bytesWritten += writeSize;
    } while (bytesWritten < len);
    return bytesWritten;
}