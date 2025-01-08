#include <cstring>
#include <elf.h>
#include <fstream>
#include <ios>
#include <iostream>
#include <filesystem>
#include <map>


namespace fs = std::filesystem;
#define SHIFT_ARGS(arr, size) do {++arr; --size; } while (0)
using FPMap = std::map<std::string, fs::file_time_type>;

class FileIO
{
private:
    std::fstream m_File;
    fs::path m_FileName;
    std::streampos m_EndPos;
    std::streampos m_SavedPos;
public:
    FileIO(fs::path const& lFingerPrintFile)
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
    ~FileIO()
    {
        if (m_File.is_open())
        {
            m_File.close();
        }
    }
    void read(void *lData, size_t const& lSize)
    {
        m_File.read(reinterpret_cast<char *>(lData), lSize);
        if (!m_File)
        {
            throw std::runtime_error("Error in reading the file:: " + m_FileName.string());
        }
    }
    bool eof()
    {
        return m_File.eof() || (m_EndPos <= m_File.tellg());
    }
    void write(const void *lData, size_t const& lSize)
    {
        m_File.write(reinterpret_cast<const char *>(lData), lSize);
        auto lCurPos = m_File.tellp();
        if (lCurPos > m_EndPos)
        {
            m_EndPos = lCurPos;
        }
    }
    bool chkSzRead(size_t const& lSzToRd)
    {
        if (m_EndPos - m_File.tellg() >= lSzToRd)
            return true;
        return false;
    }
    bool chkSzWrite(size_t const& lSzToRd)
    {
        if (m_EndPos - m_File.tellp() >= lSzToRd)
            return true;
        return false;
    }
    void seekOffWrite(std::streamoff const& lOffSz)
    {
        if(chkSzWrite(lOffSz))
            m_File.seekp(lOffSz, std::ios::cur);
        else
            m_File.seekp(0, std::ios::end);
    }
    void seekOffRead(std::streamoff const& lOffSz)
    {
        if(chkSzRead(lOffSz))
            m_File.seekg(lOffSz, std::ios::cur);
        else
            throw std::runtime_error("Attempt to seek reading beyond EOF");
    }
    void seekWrite(std::streampos const& lStrmPos)
    {
        if(m_EndPos >= lStrmPos)
            m_File.seekp(lStrmPos);
        else
            m_File.seekp(0, std::ios::end);
    }
    void saveCtxRead()
    {
        m_SavedPos = m_File.tellg();
    }
    void saveCtxWrite()
    {
        m_SavedPos = m_File.tellp();
    }
    void gotoLastCtxRead()
    {
        m_File.seekg(m_SavedPos);
    }
    void gotoLastCtxWrite()
    {
        m_File.seekp(m_SavedPos);
    }
    void seekRead(std::streampos const& lStrmPos)
    {
        if(m_EndPos >= lStrmPos)
            m_File.seekg(lStrmPos);
        else
            throw std::runtime_error("Attempt to seek reading beyond EOF");
    }
};

namespace sd
{
    constexpr auto strlen(const char* lString) -> uint32_t
    {
        const char* lStr = lString;
        while(*lStr != '\0')
        {
            ++lStr;
        }
        return (lStr - lString);
    }
}

auto crtElfHdr(const Elf64_Half lTotalSections) -> Elf64_Ehdr
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

FPMap ReadElf(fs::path const& lFingerPrintFile)
{
    FPMap lSecHdrReader;
    FileIO lFileIOStrm(lFingerPrintFile);

    try
    {
        // Read
        Elf64_Ehdr lElfHdrRead;
        if(lFileIOStrm.chkSzRead(sizeof lElfHdrRead))
            lFileIOStrm.read(&lElfHdrRead, sizeof lElfHdrRead);
        else
            throw std::runtime_error("Exceeded size of File while reading Hdr");

        auto lSzOfShHdr = lElfHdrRead.e_shentsize;
        auto lTotalSectionsRead = lElfHdrRead.e_shnum;

        lFileIOStrm.seekOffRead(lSzOfShHdr * (lTotalSectionsRead - 1));

        Elf64_Shdr lSecHdr;
        lFileIOStrm.read(&lSecHdr, sizeof lSecHdr);

        if(lSecHdr.sh_name > 1) // Not The NULL ShHdr or String Table
        {
            lFileIOStrm.seekRead(lSecHdr.sh_offset);
            std::unique_ptr<char[]> lBuffer = std::make_unique<char[]>(lSecHdr.sh_size);
            lFileIOStrm.read(lBuffer.get(), lSecHdr.sh_size);

            size_t lFileNameStrSz = 0;
            while(lFileNameStrSz + sizeof(fs::file_time_type) <= lSecHdr.sh_size)
            {
                auto const lBufStrLen = sd::strlen(lBuffer.get() + lFileNameStrSz);

                auto &lFileMTime = lSecHdrReader[std::string(lBuffer.get() + lFileNameStrSz, lBufStrLen)];
                lFileNameStrSz += lBufStrLen + 1;
                std::memcpy(&lFileMTime, lBuffer.get() + lFileNameStrSz, sizeof(fs::file_time_type));

                lFileNameStrSz += sizeof(fs::file_time_type);
            }
        }
    }
    catch(std::exception const& lExcuse)
    {
        std::cerr << lExcuse.what() << std::endl;
    }

    return lSecHdrReader;
}

void crtElf(fs::path const& lFingerPrintFile, FPMap const& lCompMap)
{
    FileIO lFileIOStrm(lFingerPrintFile);

    try
    {
        // Write
        const char lSectionName[] = "\0.String.Table\0.Siddharth.Header";

        constexpr const Elf64_Half lTotalSectionsWrite = 3;
        Elf64_Ehdr lElfHdrWrite = crtElfHdr(lTotalSectionsWrite);
        constexpr const Elf64_Off lFileShOff = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Shdr) * lTotalSectionsWrite);

        Elf64_Xword lTotFileSz = 0u, lTotLastAcc = 0u;
        for(const auto &[lFile, lAccTime] : lCompMap)
        {
            lTotFileSz += lFile.size() + 1;
            lTotLastAcc += sizeof lAccTime;
        }

        Elf64_Shdr lSecHdrWrite[lTotalSectionsWrite] = {
            Elf64_Shdr{0},
            Elf64_Shdr{.sh_name      = 1,
                       .sh_type      = SHT_STRTAB,
                       .sh_flags     = SHF_STRINGS,
                       .sh_addr      = 0x00U,
                       .sh_offset    = lFileShOff,
                       .sh_size      = sizeof lSectionName,
                       .sh_link      = SHN_UNDEF,
                       .sh_info      = 0x00U,
                       .sh_addralign = 0x01U,
                       .sh_entsize   = 0x00U},
            Elf64_Shdr{.sh_name      = 1 + sd::strlen(lSectionName + 1) + 1,
                       .sh_type      = SHT_STRTAB,
                       .sh_flags     = SHF_STRINGS,
                       .sh_addr      = 0x00U,
                       .sh_offset    = lFileShOff + sizeof lSectionName,
                       .sh_size      = lTotFileSz + lTotLastAcc,
                       .sh_link      = SHN_UNDEF,
                       .sh_info      = 0x00U,
                       .sh_addralign = 0x01U,
                       .sh_entsize   = 0x00U},
            };

        // write elf header
        lFileIOStrm.write(&lElfHdrWrite, sizeof lElfHdrWrite);

        //write elf section headers
        for(auto const &lRefSecHdr : lSecHdrWrite)
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

auto compMTime(fs::path const& lDBPath, FPMap const& lCompMap) -> bool
{
    fs::path lFingerPrintFile = lDBPath / "fingerprint";
    if (fs::exists(lFingerPrintFile))
    {
        FPMap lReadMap = ReadElf(lFingerPrintFile);

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
            crtElf(lFingerPrintFile, lCompMap);
            return true;
        }
    }
    else
    {
        crtElf(lFingerPrintFile, lCompMap);
        return true;
    }

    return true;
}

int main (int argc, char *argv[]) 
{
    std::printf("%s\n", argv[0]);
    std::printf("%s\n", __FILE__);

    auto lDBPath = fs::path(fs::current_path() / "Build" / ".fingerprint");
    if(!fs::exists(lDBPath))
        fs::create_directories(lDBPath);

    FPMap lTmpFPMap;
    lTmpFPMap[__FILE__] = fs::last_write_time(__FILE__);
    lTmpFPMap[argv[0]] = fs::last_write_time(argv[0]);

    std::cout << std::boolalpha << "rebuild needed: " << compMTime(lDBPath, lTmpFPMap) << std::endl;
    return 0;
}
