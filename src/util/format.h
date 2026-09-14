//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_FORMAT_H
#define DISASSEMBLER_FORMAT_H
#include <string>
#include <vector>

namespace util {

    enum class BinFormat {
        Elf, Macho, MachoFat, Unknown
    };

    inline BinFormat DetectBinFormat(const std::vector<uint8_t>& buffer) {
        if (buffer.size() < 4) return BinFormat::Unknown;

        uint32_t magic32 = (uint32_t(buffer[0]) << 24) | (uint32_t(buffer[1]) << 16) | (uint32_t(buffer[2]) << 8) | buffer[3];

        if (magic32 == 0x7F454C46) return BinFormat::Elf;
        if (magic32 == 0xFEEDFACE || magic32 == 0xFEEDFACF) return BinFormat::Macho;
        if (magic32 == 0xCEFAEDFE || magic32 == 0xCFFAEDFE) return BinFormat::Macho;
        if (magic32 == 0xCAFEBABE || magic32 == 0xBEBAFECA) return BinFormat::MachoFat;

        return BinFormat::Unknown;
    }
}

#endif //DISASSEMBLER_FORMAT_H
