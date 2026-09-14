//
// Created by Dmitri on 2026-09-06.
//

#include "Binary.h"

#include "../elf/ELF.h"
#include "../macho/MachO.h"

#include <stdexcept>
#include <algorithm>

util::ParsedBinary Binary::ParseBinary(const std::vector<uint8_t> &buffer) {

    util::BinFormat format = util::DetectBinFormat(buffer);
    switch (format) {
        case util::BinFormat::Unknown:
            throw std::runtime_error("Unknown binary format");
        case util::BinFormat::Macho:
            return MachO::ParseMachO(buffer);
        case util::BinFormat::Elf:
            return ELF::ParseElf(buffer);
        case util::BinFormat::MachoFat:
            throw std::runtime_error("Universal (fat) Mach-O binary detected. May have many architectures");
        default:
            throw std::runtime_error("Unknown binary format");
    }
}

util::ParsedBinary Binary::Reslice(const util::ParsedBinary &parsed, const std::vector<uint8_t> &fullBytes) {
    auto it = std::find_if(parsed.sections.begin(), parsed.sections.end(), [](const util::Section &section) {
        return section.name == ".text" || section.name == "__text";
    });

    if (it == parsed.sections.end()) {
        throw std::runtime_error("__text Section not found");
    }

    util::ParsedBinary out = parsed;
    out.fileBytes = fullBytes;

    uint64_t fileOffset = it->offset;
    if (fileOffset + it->size > fullBytes.size()) {
        throw std::runtime_error("__text Section too big");
    }

    out.text.bytes.assign(fullBytes.begin() + fileOffset, fullBytes.begin() + fileOffset + it->size);
    return out;
}