#include <cstring>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <map>
#include <memory>
#include <newTypes.hpp>
#include <sys/stat.h>

#include <boost/preprocessor/seq/for_each_i.hpp>
#include <boost/preprocessor/variadic/to_seq.hpp>

// Macro to generate each enum value with an index
#define FOR_EACH(_1, _2, i, x) x = (1 << i),

// Main macro to generate the enum definition
#define MACRO(...) BOOST_PP_SEQ_FOR_EACH_I(FOR_EACH, _, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))

#define GEN_ENUM(eName, x...)                                                  \
    enum eName : uint32_t                                                      \
    {                                                                          \
        MACRO(x)                                                               \
    }
GEN_ENUM(FileUpdateFlags, Ehdr, Shdr, Content);

namespace fs = std::filesystem;

#define SHIFT_ARGS(size, arr) do {++arr; --size; } while (0)
#define UNREACHABLE(msg) do { std::cerr << msg << std::endl; std::abort(); } while(0)

using FPMap = std::map<std::string, fs::file_time_type>;

static constexpr const Elf64_Half g_TotalSections = 3;
static constexpr const Elf64_Off g_FileShOff = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Shdr) * g_TotalSections);

template <typename TP>
constexpr auto to_sys_clock(TP tp)
{
    using namespace std::chrono;
    return time_point_cast<system_clock::duration>(tp - TP::clock::now()
              + system_clock::now());
}

template <typename TP>
constexpr std::time_t to_time_t(TP tp)
{
    using namespace std::chrono;
    auto sctp = to_sys_clock(tp);
    return system_clock::to_time_t(sctp);
}

class FileIO
{

private:

    std::fstream m_File;
    fs::path m_FileName;
    std::streampos m_EndPos;
    std::streampos m_SavedPos;

public:

    FileIO(fs::path const& lFingerPrintFile);
    ~FileIO();
    void read(void *lData, size_t const& lSize);
    bool eof();
    void write(const void *lData, size_t const& lSize);
    bool chkSzRead(size_t const& lSzToRd);
    bool chkSzWrite(size_t const& lSzToRd);
    void seekOffRead(std::streamoff const& lOffSz);
    void seekOffWrite(std::streamoff const& lOffSz);
    void seekAbsRead(std::streampos const& lStrmPos);
    void seekAbsWrite(std::streampos const& lStrmPos);
    void saveCtxRead();
    void saveCtxWrite();
    void gotoLastCtxRead();
    void gotoLastCtxWrite();
};

FileIO::FileIO(fs::path const& lFingerPrintFile)
    : m_FileName(lFingerPrintFile)
{
    m_File.open(lFingerPrintFile, std::ios::binary | std::ios::in | std::ios::out);
    if (!m_File)
    {
        m_File.open(lFingerPrintFile, std::ios::out);
        if (!m_File)
            throw std::runtime_error("Error in creating file:: " + lFingerPrintFile.string());
        m_File.close();

        m_File.open(lFingerPrintFile, std::ios::binary | std::ios::in | std::ios::out);
        if (!m_File)
            throw std::runtime_error("Error in opening file:: " + lFingerPrintFile.string());
    }

    m_File.seekg(0, std::ios::end);
    m_EndPos = m_File.tellg();
    m_File.seekg(0);
}

FileIO::~FileIO()
{
    if (m_File.is_open())
    {
        m_File.close();
    }
}

void FileIO::read(void *lData, size_t const& lSize)
{
    m_File.read(reinterpret_cast<char *>(lData), lSize);
    if (!m_File)
    {
        throw std::runtime_error("Error in reading the file:: " + m_FileName.string());
    }
}

bool FileIO::eof()
{
    return m_File.eof() || (m_EndPos <= m_File.tellg());
}

void FileIO::write(const void *lData, size_t const& lSize)
{
    m_File.write(reinterpret_cast<const char *>(lData), lSize);
    auto lCurPos = m_File.tellp();
    if (lCurPos > m_EndPos)
    {
        m_EndPos = lCurPos;
    }
}

bool FileIO::chkSzRead(size_t const& lSzToRd)
{
    if (m_EndPos - m_File.tellg() >= lSzToRd)
        return true;
    return false;
}

bool FileIO::chkSzWrite(size_t const& lSzToRd)
{
    if (m_EndPos - m_File.tellp() >= lSzToRd)
        return true;
    return false;
}

void FileIO::seekOffRead(std::streamoff const& lOffSz)
{
    if(chkSzRead(lOffSz))
        m_File.seekg(lOffSz, std::ios::cur);
    else
        throw std::runtime_error("Attempt to seek reading beyond EOF");
}

void FileIO::seekOffWrite(std::streamoff const& lOffSz)
{
    if(chkSzWrite(lOffSz))
        m_File.seekp(lOffSz, std::ios::cur);
    else
        m_File.seekp(0, std::ios::end);
}

void FileIO::seekAbsRead(std::streampos const& lStrmPos)
{
    if(m_EndPos >= lStrmPos)
        m_File.seekg(lStrmPos);
    else
        throw std::runtime_error("Attempt to seek reading beyond EOF");
}

void FileIO::seekAbsWrite(std::streampos const& lStrmPos)
{
    if(m_EndPos >= lStrmPos)
        m_File.seekp(lStrmPos);
    else
        m_File.seekp(0, std::ios::end);
}

void FileIO::saveCtxRead()
{
    m_SavedPos = m_File.tellg();
}

void FileIO::saveCtxWrite()
{
    m_SavedPos = m_File.tellp();
}

void FileIO::gotoLastCtxRead()
{
    m_File.seekg(m_SavedPos);
}

void FileIO::gotoLastCtxWrite()
{
    m_File.seekp(m_SavedPos);
}

namespace sd
{
    constexpr u32 strlen(const char* lString)
    {
        const char* lStr = lString;
        while(*lStr != '\0')
        {
            ++lStr;
        }
        return (lStr - lString);
    }

    constexpr const char *strrchr(const char *lStart, size_t lStrSize, char lCharToMatch)
    {
        const char *lStrEnd = lStart + lStrSize;
        while (--lStrEnd >= lStart)
        {
            if (*lStrEnd == lCharToMatch)
            {
                return lStrEnd + 1; // Return pointer to character after the match
            }
        }
        return lStart; // If no match found, return start of the string
    }
}

Elf64_Ehdr crtElfHdr(const Elf64_Half lTotalSections)
{
    Elf64_Ehdr lElfHdr = {
        .e_ident = {
            [EI_MAG0] = ELFMAG0,
            [EI_MAG1] = ELFMAG1,
            [EI_MAG2] = ELFMAG2,
            [EI_MAG3] = ELFMAG3,
            [EI_CLASS] = ELFCLASS64,
            [EI_DATA] = ELFDATA2LSB,
            [EI_VERSION] = EV_CURRENT,
            [EI_OSABI] = ELFOSABI_NONE,
            [EI_ABIVERSION] = 0x00,
        },
        .e_type = ET_NONE,
        .e_machine = EM_NONE,
        .e_version = EV_CURRENT,
        .e_entry = 0x00U,
        .e_phoff = 0x00U,
        .e_shoff = sizeof lElfHdr,
        .e_flags = 0x00U,
        .e_ehsize = sizeof lElfHdr,
        .e_phentsize = 0x00U,
        .e_phnum = 0x00U,
        .e_shentsize = sizeof(Elf64_Shdr),
        .e_shnum = lTotalSections,
        .e_shstrndx = 1
    };

    std::memset(lElfHdr.e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD);
    return lElfHdr;
}

void crtElf(fs::path const& lFingerPrintFile, FPMap const& lCompMap)
{
    try
    {
        // Write
        Elf64_Ehdr lElfHdr = crtElfHdr(g_TotalSections);

        const char lSectionName[] = "\0.String.Table\0.mTime.Header";
        Elf64_Xword lTotFileSz = 0u, lTotLastAcc = 0u;
        for(const auto &[lFile, lAccTime] : lCompMap)
        {
            lTotFileSz += lFile.size() + 1;
            lTotLastAcc += sizeof lAccTime;
        }

        Elf64_Shdr lSecHdr[g_TotalSections] = {
            Elf64_Shdr{0},
            Elf64_Shdr{.sh_name      = 1,
                       .sh_type      = SHT_STRTAB,
                       .sh_flags     = SHF_STRINGS,
                       .sh_addr      = 0x00U,
                       .sh_offset    = g_FileShOff,
                       .sh_size      = sizeof lSectionName,
                       .sh_link      = SHN_UNDEF,
                       .sh_info      = 0x00U,
                       .sh_addralign = 0x01U,
                       .sh_entsize   = 0x00U},
            Elf64_Shdr{.sh_name      = 1 + sd::strlen(lSectionName + 1) + 1,
                       .sh_type      = SHT_STRTAB,
                       .sh_flags     = SHF_STRINGS,
                       .sh_addr      = 0x00U,
                       .sh_offset    = g_FileShOff + sizeof lSectionName,
                       .sh_size      = lTotFileSz + lTotLastAcc,
                       .sh_link      = SHN_UNDEF,
                       .sh_info      = 0x00U,
                       .sh_addralign = 0x01U,
                       .sh_entsize   = 0x00U},
            };

        FileIO lFileIOStrm(lFingerPrintFile);

        // write elf header
        lFileIOStrm.write(&lElfHdr, sizeof lElfHdr);

        //write elf section headers
        for(auto const &lRefSecHdr : lSecHdr)
        {
            lFileIOStrm.write(&lRefSecHdr, sizeof lRefSecHdr);
        }
        lFileIOStrm.write(lSectionName, sizeof lSectionName);

        // FileName\0[8bytes]LastAccess ...
        for(const auto &[lFile, lAccTime] : lCompMap)
        {
            lFileIOStrm.write(lFile.c_str(), lFile.size() + 1);
            lFileIOStrm.write(&lAccTime, sizeof lAccTime);
        }
    }
    catch(std::exception const& lExcuse)
    {
        std::cerr << lExcuse.what() << std::endl;
    }
}

FPMap ReadElf(fs::path const& lFingerPrintFile)
{
    FPMap lLastAccMap;
    try
    {
        // Read
        FileIO lFileIOStrm(lFingerPrintFile);

        Elf64_Ehdr lElfHdr;
        if(lFileIOStrm.chkSzRead(sizeof lElfHdr))
            lFileIOStrm.read(&lElfHdr, sizeof lElfHdr);
        else
            throw std::runtime_error("Exceeded size of File while reading Hdr");

        auto lSzOfShHdr = lElfHdr.e_shentsize;
        auto lTotalSections = lElfHdr.e_shnum;

        lFileIOStrm.seekOffRead(lSzOfShHdr * (lTotalSections - 1));

        Elf64_Shdr lSecHdr;
        lFileIOStrm.read(&lSecHdr, sizeof lSecHdr);

        if(lSecHdr.sh_name > 1) // Not The NULL ShHdr or String Table
        {
            lFileIOStrm.seekAbsRead(lSecHdr.sh_offset);
            std::unique_ptr<char[]> lBuffer = std::make_unique<char[]>(lSecHdr.sh_size);
            lFileIOStrm.read(lBuffer.get(), lSecHdr.sh_size);

            size_t lFileNameStrSz = 0;
            while(lFileNameStrSz + sizeof(fs::file_time_type) <= lSecHdr.sh_size)
            {
                auto const lBufStrLen = sd::strlen(lBuffer.get() + lFileNameStrSz);

                auto &lFileMTime = lLastAccMap[std::string(lBuffer.get() + lFileNameStrSz, lBufStrLen)];
                lFileNameStrSz += lBufStrLen + 1;
                std::memcpy(&lFileMTime, lBuffer.get() + lFileNameStrSz, sizeof(fs::file_time_type));

                lFileNameStrSz += sizeof(fs::file_time_type);
            }
        }
        else
        {
            UNREACHABLE("Improper offsets while reading from file or corrupt file");
        }
    }
    catch(std::exception const& lExcuse)
    {
        std::cerr << lExcuse.what() << std::endl;
    }

    return lLastAccMap;
}

void updateElf(u32 const flags)
{
    if(flags & FileUpdateFlags::Ehdr)
    {
        std::cout << "ELF Header" << std::endl;
    }
    if(flags & FileUpdateFlags::Shdr)
    {
        std::cout << "ELF Section Header" << std::endl;
    }
    if(flags & FileUpdateFlags::Content)
    {
        std::cout << "ELF Content" << std::endl;
    }
}

bool compMTime(fs::path const& lFPFile, FPMap const& lCompMap)
{
    if (fs::exists(lFPFile))
    {
        FPMap lReadMap = ReadElf(lFPFile);

        try
        {
            for(const auto &[lFPFileName, lFPMTime] : lCompMap)
            {
                if (lReadMap.at(lFPFileName) != lFPMTime)
                {
                    throw std::runtime_error("Recrt ELF mTime mismatched");
                }
            }
            return false;
        }
        catch(std::exception const& lExcuse)
        {
            std::cerr << lExcuse.what() << std::endl;
            crtElf(lFPFile, lCompMap);
            return true;
        }
    }
    else
    {
        crtElf(lFPFile, lCompMap);
        return true;
    }

    return true;
}

fs::path getCurBinPath()
{
    struct stat sb;
    if(lstat("/proc/self/exe", &sb) == -1)
    {
        UNREACHABLE("Couldn't lstat /proc/self/exe");
    }

    u64 lCurFilePathSz = 1 << 9;
    i64 lRdLnkVal = 0;
    std::unique_ptr<char[]> lCurFilePath = nullptr;

    constexpr static u64 lMaxVal = u64::MAX / 100;

    do
    {
        if (lCurFilePathSz > lMaxVal)
        {
            UNREACHABLE("Reached Max allocation depth");
        }

        lCurFilePathSz = lCurFilePathSz << 1;
        lCurFilePath = std::make_unique<char[]>(lCurFilePathSz);

        lRdLnkVal = readlink("/proc/self/exe", lCurFilePath.get(), lCurFilePathSz);
        if (lRdLnkVal == -1) 
        {
            UNREACHABLE("couldn't read /proc/self/exe");
        }
    } while(lRdLnkVal == lCurFilePathSz);

    lCurFilePath[lRdLnkVal] = '\0';
    return fs::path(lCurFilePath.get(), lCurFilePath.get() + lRdLnkVal);
}

int main (int argc, char *argv[]) 
{
    SHIFT_ARGS(argc, argv);
    fs::path lCurBinFile = getCurBinPath();
    fs::path lCurBinPath = lCurBinFile.parent_path();
    if (lCurBinPath.filename() != "build")
    {
        lCurBinPath /= "build";
        auto lTmpBinFile = lCurBinPath / lCurBinFile.filename();

        fs::create_directory(lCurBinPath);        

        fs::rename(lCurBinFile, lTmpBinFile);
        std::swap(lCurBinFile, lTmpBinFile);
        fs::create_symlink(lCurBinFile, lTmpBinFile);
    }

    fs::path lSrcFilePath = lCurBinPath.parent_path();
    fs::path lSrcFile = lSrcFilePath / __FILE_NAME__;

    auto lFPFile = fs::path(lCurBinPath / ".fingerprint");

    FPMap lTmpFPMap;
    lTmpFPMap[lSrcFile.string()] = fs::last_write_time(lSrcFile);
    lTmpFPMap[lCurBinFile.string()] = fs::last_write_time(lCurBinFile);

    std::cout << std::boolalpha << "rebuild needed: " << compMTime(lFPFile, lTmpFPMap) << std::endl;
    return 0;
}
