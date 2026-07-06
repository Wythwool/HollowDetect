#include "hollowdet/peparse.h"
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <utility>

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

struct IMAGE_SECTION_HEADER_ {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR_ {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct IMAGE_EXPORT_DIRECTORY_ {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};
#pragma pack(pop)

static std::string SectionName(const uint8_t name[8]){
    size_t n = 0;
    while (n < 8 && name[n] != 0) {
        ++n;
    }
    return std::string(reinterpret_cast<const char*>(name), n);
}

template <typename T>
static bool ReadPod(const unsigned char* data, size_t size, size_t offset, T& out) {
    if (offset > size || size - offset < sizeof(T)) {
        return false;
    }
    std::memcpy(&out, data + offset, sizeof(T));
    return true;
}

static std::vector<size_t> RvaOffsets(const PeQuick& pe, size_t size, uint32_t rva) {
    std::vector<size_t> out;
    if (rva < size) {
        out.push_back(rva);
    }
    for (const auto& section : pe.section_table) {
        uint32_t span = std::max<uint32_t>(section.virtual_size, section.raw_size);
        uint64_t start = section.virtual_address;
        uint64_t end = start + span;
        if (span == 0 || rva < start || rva >= end) {
            continue;
        }
        uint64_t mapped = static_cast<uint64_t>(section.raw_offset) + (rva - section.virtual_address);
        if (mapped < size) {
            size_t off = static_cast<size_t>(mapped);
            if (std::find(out.begin(), out.end(), off) == out.end()) {
                out.push_back(off);
            }
        }
    }
    return out;
}

template <typename T>
static bool ReadPodRva(const unsigned char* data, size_t size, const PeQuick& pe, uint32_t rva, T& out) {
    for (size_t off : RvaOffsets(pe, size, rva)) {
        if (ReadPod(data, size, off, out)) {
            return true;
        }
    }
    return false;
}

static std::string ReadCStringAt(const unsigned char* data, size_t size, size_t offset, size_t max_len = 260) {
    if (offset >= size) {
        return {};
    }
    std::string out;
    for (size_t i = offset; i < size && out.size() < max_len; ++i) {
        unsigned char ch = data[i];
        if (ch == 0) {
            return out;
        }
        if (ch < 0x20 || ch > 0x7e) {
            return {};
        }
        out.push_back(static_cast<char>(ch));
    }
    return {};
}

static std::string ReadCStringRva(const unsigned char* data, size_t size, const PeQuick& pe, uint32_t rva) {
    for (size_t off : RvaOffsets(pe, size, rva)) {
        std::string value = ReadCStringAt(data, size, off);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

static bool IsZeroImportDescriptor(const IMAGE_IMPORT_DESCRIPTOR_& desc) {
    return desc.OriginalFirstThunk == 0 &&
           desc.TimeDateStamp == 0 &&
           desc.ForwarderChain == 0 &&
           desc.Name == 0 &&
           desc.FirstThunk == 0;
}

static void ParseImports(const unsigned char* data, size_t size, PeQuick& out) {
    if (out.import_rva == 0 || out.import_size < sizeof(IMAGE_IMPORT_DESCRIPTOR_)) {
        return;
    }

    size_t table_offset = size;
    for (size_t off : RvaOffsets(out, size, out.import_rva)) {
        IMAGE_IMPORT_DESCRIPTOR_ first{};
        if (!ReadPod(data, size, off, first) || IsZeroImportDescriptor(first)) {
            continue;
        }
        if (!ReadCStringRva(data, size, out, first.Name).empty()) {
            table_offset = off;
            break;
        }
    }
    if (table_offset == size) {
        return;
    }

    size_t descriptor_limit = std::min<size_t>(64, out.import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR_) + 1);
    for (size_t i = 0; i < descriptor_limit; ++i) {
        IMAGE_IMPORT_DESCRIPTOR_ desc{};
        size_t desc_offset = table_offset + i * sizeof(desc);
        if (!ReadPod(data, size, desc_offset, desc) || IsZeroImportDescriptor(desc)) {
            break;
        }

        PeImportDll dll{};
        dll.dll = ReadCStringRva(data, size, out, desc.Name);
        if (dll.dll.empty()) {
            continue;
        }

        uint32_t thunk_rva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
        if (thunk_rva != 0) {
            size_t thunk_size = out.is64 ? sizeof(uint64_t) : sizeof(uint32_t);
            for (size_t thunk_offset : RvaOffsets(out, size, thunk_rva)) {
                std::vector<std::string> names;
                uint32_t ordinal_count = 0;
                for (size_t n = 0; n < 256; ++n) {
                    uint64_t thunk = 0;
                    size_t off = thunk_offset + n * thunk_size;
                    if (out.is64) {
                        if (!ReadPod(data, size, off, thunk)) {
                            break;
                        }
                    } else {
                        uint32_t value = 0;
                        if (!ReadPod(data, size, off, value)) {
                            break;
                        }
                        thunk = value;
                    }
                    if (thunk == 0) {
                        break;
                    }

                    uint64_t ordinal_mask = out.is64 ? 0x8000000000000000ull : 0x80000000ull;
                    if ((thunk & ordinal_mask) != 0) {
                        ++ordinal_count;
                        continue;
                    }

                    uint32_t name_rva = static_cast<uint32_t>(thunk & 0xffffffffu);
                    for (size_t name_offset : RvaOffsets(out, size, name_rva)) {
                        std::string name = ReadCStringAt(data, size, name_offset + sizeof(uint16_t));
                        if (!name.empty()) {
                            names.push_back(name);
                            break;
                        }
                    }
                }
                if (!names.empty() || ordinal_count != 0) {
                    dll.names = std::move(names);
                    dll.ordinal_count = ordinal_count;
                    break;
                }
            }
        }
        out.imports.push_back(std::move(dll));
    }
}

static void ParseExports(const unsigned char* data, size_t size, PeQuick& out) {
    if (out.export_rva == 0 || out.export_size < sizeof(IMAGE_EXPORT_DIRECTORY_)) {
        return;
    }

    IMAGE_EXPORT_DIRECTORY_ dir{};
    bool found = false;
    for (size_t off : RvaOffsets(out, size, out.export_rva)) {
        if (ReadPod(data, size, off, dir) && dir.NumberOfNames != 0 && dir.AddressOfNames != 0) {
            found = true;
            break;
        }
    }
    if (!found) {
        return;
    }

    uint32_t count = std::min<uint32_t>(dir.NumberOfNames, 512);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t name_rva = 0;
        if (!ReadPodRva(data, size, out, dir.AddressOfNames + i * sizeof(uint32_t), name_rva)) {
            break;
        }
        std::string name = ReadCStringRva(data, size, out, name_rva);
        if (!name.empty()) {
            out.exports.push_back(name);
        }
    }
}

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
        if (opt->NumberOfRvaAndSizes > 0) {
            out.export_rva = opt->DataDirectory[0].VirtualAddress;
            out.export_size = opt->DataDirectory[0].Size;
        }
        if (opt->NumberOfRvaAndSizes > 1) {
            out.import_rva = opt->DataDirectory[1].VirtualAddress;
            out.import_size = opt->DataDirectory[1].Size;
        }
        out.has_clr = opt->NumberOfRvaAndSizes > 14 &&
                      opt->DataDirectory[14].VirtualAddress != 0 &&
                      opt->DataDirectory[14].Size != 0;
    } else if (magic == 0x20b && opt_offset + sizeof(IMAGE_OPTIONAL_HEADER64_) <= size) {
        auto opt = (const IMAGE_OPTIONAL_HEADER64_*)(data + opt_offset);
        out.is64 = true;
        out.entry_rva = opt->AddressOfEntryPoint;
        out.image_base = opt->ImageBase;
        out.size_of_image = opt->SizeOfImage;
        out.checksum = opt->CheckSum;
        out.subsystem = opt->Subsystem;
        if (opt->NumberOfRvaAndSizes > 0) {
            out.export_rva = opt->DataDirectory[0].VirtualAddress;
            out.export_size = opt->DataDirectory[0].Size;
        }
        if (opt->NumberOfRvaAndSizes > 1) {
            out.import_rva = opt->DataDirectory[1].VirtualAddress;
            out.import_size = opt->DataDirectory[1].Size;
        }
        out.has_clr = opt->NumberOfRvaAndSizes > 14 &&
                      opt->DataDirectory[14].VirtualAddress != 0 &&
                      opt->DataDirectory[14].Size != 0;
    }

    size_t section_offset = opt_offset + file->SizeOfOptionalHeader;
    size_t max_sections = std::min<size_t>(file->NumberOfSections, 96);
    for (size_t i = 0; i < max_sections; ++i) {
        size_t off = section_offset + i * sizeof(IMAGE_SECTION_HEADER_);
        if (off + sizeof(IMAGE_SECTION_HEADER_) > size) {
            break;
        }
        auto sec = (const IMAGE_SECTION_HEADER_*)(data + off);
        PeSection item{};
        item.name = SectionName(sec->Name);
        item.virtual_address = sec->VirtualAddress;
        item.virtual_size = sec->VirtualSize;
        item.raw_offset = sec->PointerToRawData;
        item.raw_size = sec->SizeOfRawData;
        item.characteristics = sec->Characteristics;
        out.section_table.push_back(item);
    }
    ParseImports(data, size, out);
    ParseExports(data, size, out);
    return out;
}

} // namespace hollow
