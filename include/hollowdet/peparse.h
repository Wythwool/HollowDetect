#pragma once
#include <cstdint>
#include <cstddef>

namespace hollow {

struct PeQuick {
    bool valid = false;
    bool is64 = false;
    uint16_t machine = 0;
    uint16_t sections = 0;
    uint16_t characteristics = 0;
    uint16_t subsystem = 0;
    uint16_t optional_magic = 0;
    uint32_t timestamp = 0;
    uint32_t entry_rva = 0;
    uint32_t size_of_image = 0;
    uint32_t checksum = 0;
    uint64_t image_base = 0;
};

// Parse a compact PE identity from memory or file bytes.
PeQuick ParsePe(const unsigned char* data, size_t size);

} // namespace hollow
