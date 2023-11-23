#include "KittyUtils.hpp"

namespace KittyUtils
{

#ifdef __ANDROID__
    std::string getExternalStorage()
    {
        char *storage = getenv("EXTERNAL_STORAGE");
        return storage ? storage : "/sdcard";
    }

    int getAndroidVersion()
    {
        static int ver = 0;
        if (ver > 0)
            return ver;

        char buf[0xff] = { 0 };
        if (__system_property_get("ro.build.version.release", buf))
            ver = std::atoi(buf);

        return ver;
    }

    int getAndroidSDK()
    {
        static int sdk = 0;
        if (sdk > 0)
            return sdk;

        char buf[0xff] = { 0 };
        if (__system_property_get("ro.build.version.sdk", buf))
            sdk = std::atoi(buf);

        return sdk;
    }
#endif

    std::string fileNameFromPath(const std::string &filePath)
    {
        std::string filename;
        const size_t last_slash_idx = filePath.find_last_of("/\\");
        if (std::string::npos != last_slash_idx)
            filename = filePath.substr(last_slash_idx + 1);
        return filename;
    }

     std::string fileDirectory(const std::string &filePath)
    {
        std::string directory;
        const size_t last_slash_idx = filePath.find_last_of("/\\");
        if (std::string::npos != last_slash_idx)
            directory = filePath.substr(0, last_slash_idx);
        return directory;
    }

    std::string fileExtension(const std::string &filePath)
    {
        std::string ext;
        const size_t last_slash_idx = filePath.find_last_of(".");
        if (std::string::npos != last_slash_idx)
            ext = filePath.substr(last_slash_idx + 1);
        return ext;
    }

    void String::Trim(std::string &str)
    {
        // https://www.techiedelight.com/remove-whitespaces-string-cpp/
        str.erase(std::remove_if(str.begin(), str.end(), [](char c)
                                 { return (c == ' ' || c == '\n' || c == '\r' ||
                                           c == '\t' || c == '\v' || c == '\f'); }),
                  str.end());
    }

    bool String::ValidateHex(std::string &hex)
    {
        if (hex.empty())
            return false;

        if (hex.compare(0, 2, "0x") == 0)
            hex.erase(0, 2);

        Trim(hex); // first remove spaces

        if (hex.length() < 2 || hex.length() % 2 != 0)
            return false;

        for (size_t i = 0; i < hex.length(); i++)
        {
            if (!std::isxdigit((unsigned char)hex[i]))
                return false;
        }

        return true;
    }

    std::string String::Random(size_t length)
    {
        static const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        
        thread_local static std::default_random_engine rnd(std::random_device{}());
        thread_local static std::uniform_int_distribution<std::string::size_type> dist(0, chars.size()-1);

        std::string str(length, '\0');
        for (size_t i = 0; i < length; ++i)
            str[i] = chars[dist(rnd)];

        return str;
    }

    std::string String::Fmt(const char *fmt, ...)
    {
        if (!fmt)
            return "";

        va_list args;

        va_start(args, fmt);
        size_t size = vsnprintf(nullptr, 0, fmt, args) + 1; // extra space for '\0'
        va_end(args);

        std::vector<char> buffer(size, '\0');

        va_start(args, fmt);
        vsnprintf(&buffer[0], size, fmt, args);
        va_end(args);

        return std::string(&buffer[0]);
    }

    // https://tweex.net/post/c-anything-tofrom-a-hex-string/

    /*
        Convert a block of data to a hex string
    */
    std::string data2Hex(
        const void *data,       //!< Data to convert
        const size_t dataLength //!< Length of the data to convert
    )
    {
        const auto *byteData = reinterpret_cast<const unsigned char *>(data);
        std::stringstream hexStringStream;

        hexStringStream << std::hex << std::setfill('0');
        for (size_t index = 0; index < dataLength; ++index)
            hexStringStream << std::setw(2) << static_cast<int>(byteData[index]);
        return hexStringStream.str();
    }

    /*
        Convert a hex string to a block of data
    */
    void dataFromHex(
        const std::string &in, //!< Input hex string
        void *data             //!< Data store
    )
    {
        size_t length = in.length();
        auto *byteData = reinterpret_cast<unsigned char *>(data);

        std::stringstream hexStringStream;
        hexStringStream >> std::hex;
        for (size_t strIndex = 0, dataIndex = 0; strIndex < length; ++dataIndex)
        {
            // Read out and convert the string two characters at a time
            const char tmpStr[3] = {in[strIndex++], in[strIndex++], 0};

            // Reset and fill the string stream
            hexStringStream.clear();
            hexStringStream.str(tmpStr);

            // Do the conversion
            int tmpValue = 0;
            hexStringStream >> tmpValue;
            byteData[dataIndex] = static_cast<unsigned char>(tmpValue);
        }
    }

}