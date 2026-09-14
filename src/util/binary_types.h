//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_BINARY_TYPES_H
#define DISASSEMBLER_BINARY_TYPES_H
#include <string>
#include <vector>

#include "format.h"

namespace util {
    struct Section {
        std::string name;
        std::string segment;

        uint32_t type;
        uint64_t flags;
        uint64_t addr;
        uint64_t offset;
        uint64_t size;
        uint32_t link;
        uint32_t info;
        uint64_t entsize;
        uint32_t reserved1;
        uint32_t reserved2;
    };

    struct Symbol {
        std::string name;
        uint64_t addr;
        uint64_t size;
        bool external;
    };

    struct TextInfo {
        std::vector<uint8_t> bytes;
        uint64_t baseAddr;
        uint64_t fileOffset;
        uint64_t size;
    };

    struct ElfHeaderInfo {
        bool is64 = true;
        bool le = true;
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_entry;
        uint64_t e_phoff;
        uint64_t e_shoff;
        uint64_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
    };

    struct MachoHeaderInfo {
        uint32_t magic;
        bool le = true;
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;
        uint32_t headerSize = 32;
    };

    struct ParsedBinary {
        BinFormat format = BinFormat::Unknown;
        std::vector<uint8_t> fileBytes;
        ElfHeaderInfo elfHeader;
        MachoHeaderInfo machoHeader;

        std::vector<Section> sections;
        std::vector<Symbol> symbols;
        TextInfo text;
    };
}
#endif //DISASSEMBLER_BINARY_TYPES_H
