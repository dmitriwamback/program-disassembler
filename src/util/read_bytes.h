//
// Created by Dmitri on 2026-09-14.
//

#ifndef DISASSEMBLER_READ_BYTES_H
#define DISASSEMBLER_READ_BYTES_H
#include <cstdint>
#include <vector>
#include <string>

namespace util {
    inline uint8_t readU8(const std::vector<uint8_t>& b, uint64_t off) {
        if (off + 1 > b.size()) throw std::runtime_error("readU8 read out of bounds");
        return b[off];
    }

    inline uint16_t readU16(const std::vector<uint8_t>& b, uint64_t off, bool le = true) {
        if (off + 2 > b.size()) throw std::runtime_error("readU16 read out of bounds");
        uint16_t v = uint16_t(b[off]) | (uint16_t(b[off + 1]) << 8);
        return le ? v : uint16_t((v << 8) | (v >> 8));
    }

    inline uint32_t readU32(const std::vector<uint8_t>& b, uint64_t off, bool le = true) {
        if (off + 4 > b.size()) throw std::runtime_error("readU32 read out of bounds");
        uint32_t v = uint32_t(b[off]) | (uint32_t(b[off + 1]) << 8) | (uint32_t(b[off + 2]) << 16) |
                     (uint32_t(b[off + 3]) << 24);
        return le ? v : __builtin_bswap32(v);
    }

    inline uint64_t readU64(const std::vector<uint8_t>& b, uint64_t off, bool le = true) {
        uint64_t lo = readU32(b, off, le);
        uint64_t hi = readU32(b, off + 4, le);
        return le ? (lo | (hi << 32)) : ((lo << 32) | hi);
    }

    inline uint16_t readU16LE(const std::vector<uint8_t>& buffer, uint64_t offset) {
        if (offset + 2 > buffer.size()) {
            throw std::out_of_range("ELF: Out of bounds");
        }
        return static_cast<uint16_t>(buffer[offset]) | static_cast<uint16_t>(buffer[offset + 1] << 8);
    }


    inline uint32_t readU32LE(const std::vector<uint8_t>& buffer, uint64_t offset) {
        if (offset + 4 > buffer.size()) {
            throw std::out_of_range("ELF: Out of bounds");
        }
        return static_cast<uint32_t>(buffer[offset]) | static_cast<uint32_t>(buffer[offset + 1] << 8) | static_cast<uint32_t>(buffer[offset + 2] << 16) | static_cast<uint32_t>(buffer[offset + 3] << 24);
    }

    inline uint64_t readU64LE(const std::vector<uint8_t>& buffer, uint64_t offset) {
        if (offset + 8 > buffer.size()) {
            throw std::out_of_range("ELF: Out of bounds");
        }
        uint64_t lo = readU32LE(buffer, offset);
        uint64_t hi = readU32LE(buffer, offset + 4);

        return lo | (hi << 32);
    }

    inline std::string readCString(const std::vector<uint8_t>& buf, uint64_t offset, uint64_t maxLen = UINT64_MAX) {
        if (offset >= buf.size()) return "";
        uint64_t cap = std::min<uint64_t>(maxLen, buf.size() - offset);
        uint64_t end = 0;
        while (end < cap && buf[offset + end] != 0) end++;
        return std::string(reinterpret_cast<const char*>(&buf[offset]), end);
    }
}

#endif //DISASSEMBLER_READ_BYTES_H
