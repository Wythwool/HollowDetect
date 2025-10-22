#include "hollowdet/peparse.h"
#include <cstdint>
#include <cstring>

namespace hollow {

#pragma pack(push,1)
struct IMAGE_DOS_HEADER_ {
    uint16_t e_magic;    // 'MZ'
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;   // file address of new exe header
};

struct IMAGE_FILE_HEADER_ {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY_ { uint32_t VirtualAddress; uint32_t Size; };

struct IMAGE_OPTIONAL_HEADER64_ {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_ DataDirectory[16];
};

struct IMAGE_NT_HEADERS64_ {
    uint32_t Signature; // 'PE\0\0'
    IMAGE_FILE_HEADER_ FileHeader;
    IMAGE_OPTIONAL_HEADER64_ OptionalHeader;
};
#pragma pack(pop)

PeQuick ParsePe(const unsigned char* data, size_t size){
    PeQuick out{};
    if (size < 0x1000) return out;
    auto dos = (const IMAGE_DOS_HEADER_*)data;
    if (dos->e_magic != 0x5A4D) return out; // 'MZ'
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64_) > size) return out;
    auto nt = (const IMAGE_NT_HEADERS64_*)(data + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return out; // 'PE\0\0'
    out.valid = true;
    out.machine = nt->FileHeader.Machine;
    out.sections = nt->FileHeader.NumberOfSections;
    out.entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    return out;
}

} // namespace hollow
