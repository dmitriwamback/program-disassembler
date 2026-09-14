//
// Created by Dmitri on 2026-09-14.
//

#ifndef DISASSEMBLER_WRITE_BYTES_H
#define DISASSEMBLER_WRITE_BYTES_H
#include <cstdint>
#include <vector>

namespace util {
    inline void writeU32(std::vector<uint8_t>& buffer, uint64_t offset, uint32_t value) {
        if (offset + 4 > buffer.size()) {
            throw std::out_of_range("Out of bounds");
        }
        *reinterpret_cast<uint32_t*>(&buffer[offset]) = value;
    }
}

#endif //DISASSEMBLER_WRITE_BYTES_H
