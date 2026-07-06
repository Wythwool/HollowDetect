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

struct IMAGE_OPTIONAL_HEADER32_ {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
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
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_ DataDirectory[16];
};

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
    if (size < sizeof(IMAGE_DOS_HEADER_)) return out;
    auto dos = (const IMAGE_DOS_HEADER_*)data;
    if (dos->e_magic != 0x5A4D) return out; // 'MZ'
    if (dos->e_lfanew <= 0) return out;
    size_t nt_offset = static_cast<size_t>(dos->e_lfanew);
    if (nt_offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_) > size) return out;
    uint32_t sig = *(const uint32_t*)(data + nt_offset);
    if (sig != 0x00004550) return out; // 'PE\0\0'
    auto file = (const IMAGE_FILE_HEADER_*)(data + nt_offset + sizeof(uint32_t));
    out.valid = true;
    out.machine = file->Machine;
    out.sections = file->NumberOfSections;
    out.timestamp = file->TimeDateStamp;
    out.characteristics = file->Characteristics;

    size_t opt_offset = nt_offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_);
    if (file->SizeOfOptionalHeader < sizeof(uint16_t) || opt_offset + sizeof(uint16_t) > size) {
        return out;
    }
    uint16_t magic = *(const uint16_t*)(data + opt_offset);
    out.optional_magic = magic;
    if (magic == 0x10b && opt_offset + sizeof(IMAGE_OPTIONAL_HEADER32_) <= size) {
        auto opt = (const IMAGE_OPTIONAL_HEADER32_*)(data + opt_offset);
        out.is64 = false;
        out.entry_rva = opt->AddressOfEntryPoint;
        out.image_base = opt->ImageBase;
        out.size_of_image = opt->SizeOfImage;
        out.checksum = opt->CheckSum;
        out.subsystem = opt->Subsystem;
    } else if (magic == 0x20b && opt_offset + sizeof(IMAGE_OPTIONAL_HEADER64_) <= size) {
        auto opt = (const IMAGE_OPTIONAL_HEADER64_*)(data + opt_offset);
        out.is64 = true;
        out.entry_rva = opt->AddressOfEntryPoint;
        out.image_base = opt->ImageBase;
        out.size_of_image = opt->SizeOfImage;
        out.checksum = opt->CheckSum;
        out.subsystem = opt->Subsystem;
    }
    return out;
}

} // namespace hollow
