#pragma once
#include <cstdint>
#include <cstddef>

namespace hollow {

struct PeQuick {
    bool valid = false;
    uint16_t machine = 0;
    uint16_t sections = 0;
    uint32_t entry_rva = 0;
};

// Parse minimal PE header from memory block (process bytes), expect at least 0x1000.
PeQuick ParsePe(const unsigned char* data, size_t size);

} // namespace hollow
