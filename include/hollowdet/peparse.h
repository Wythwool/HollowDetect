#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace hollow {

struct PeSection {
    std::string name;
    uint32_t virtual_address = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_offset = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0;
};

struct PeImportDll {
    std::string dll;
    std::vector<std::string> names;
    uint32_t ordinal_count = 0;
};

struct PeQuick {
    bool valid = false;
    bool is64 = false;
    bool has_clr = false;
    uint16_t machine = 0;
    uint16_t sections = 0;
    uint16_t characteristics = 0;
    uint16_t subsystem = 0;
    uint16_t optional_magic = 0;
    uint32_t timestamp = 0;
    uint32_t entry_rva = 0;
    uint32_t size_of_image = 0;
    uint32_t checksum = 0;
    uint32_t import_rva = 0;
    uint32_t import_size = 0;
    uint32_t export_rva = 0;
    uint32_t export_size = 0;
    uint64_t image_base = 0;
    std::vector<PeSection> section_table;
    std::vector<PeImportDll> imports;
    std::vector<std::string> exports;
};

// Parse a compact PE identity from memory or file bytes.
PeQuick ParsePe(const unsigned char* data, size_t size);

} // namespace hollow
