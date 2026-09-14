//
// Created by Dmitri on 2026-09-06.
//

#include "Patcher.h"

#include "util/format.h"
#include "util/read_bytes.h"
#include "util/write_bytes.h"

TextSection Patcher::FindTextMachO(const std::vector<uint8_t> &data) {
    if (data.size() < 32) {
        throw std::out_of_range("MachO: Out of bounds");
    }

    uint32_t cputype = *reinterpret_cast<const uint32_t*>(&data[4]);
    bool isArm64 = (cputype == 0x0100000C);

    uint32_t ncmds = *reinterpret_cast<const uint32_t*>(&data[16]);
    size_t offset = 32;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (offset + 8 > data.size()) {
            break;
        }
        uint32_t cmd = *reinterpret_cast<const uint32_t*>(&data[offset]);
        uint32_t cmdsize = *reinterpret_cast<const uint32_t*>(&data[offset + 4]);

        if (cmd == 0x19) {
            uint32_t nsects = *reinterpret_cast<const uint32_t*>(&data[offset + 64]);
            size_t sectoff = offset + 72;

            for (uint32_t j = 0; j < nsects; j++) {
                std::string sectname(reinterpret_cast<const char*>(&data[sectoff]), 16);
                std::string segname(reinterpret_cast<const char*>(&data[sectoff + 16]), 16);
                uint64_t addr       = *reinterpret_cast<const uint64_t*>(&data[sectoff + 32]);
                uint64_t size       = *reinterpret_cast<const uint64_t*>(&data[sectoff + 40]);
                uint64_t fileoff    = *reinterpret_cast<const uint64_t*>(&data[sectoff + 48]);

                sectoff += 80;

                if (sectname == "__text" && segname == "__TEXT") {
                    return {fileoff, addr, isArm64};
                }
            }
        }
        offset += cmdsize;
    }
    throw std::out_of_range("Could not find __TEXT,__text");
}

TextSection Patcher::FindTextELF(const std::vector<uint8_t> &data) {
    if (data.size() <40) {
        throw std::out_of_range("ELF: Out of bounds");
    }

    uint16_t e_machine = *reinterpret_cast<const uint16_t*>(&data[0x12]);
    bool isArm64 = (e_machine == 0xB7);

    uint64_t e_shoff        = *reinterpret_cast<const uint64_t*>(&data[0x28]);
    uint64_t e_shentsize    = *reinterpret_cast<const uint64_t*>(&data[0x3A]);
    uint64_t e_shnum        = *reinterpret_cast<const uint64_t*>(&data[0x3C]);
    uint64_t e_shstrndx     = *reinterpret_cast<const uint64_t*>(&data[0x3E]);

    auto sectionHeader = [&](int i) -> const uint8_t* {
        return &data[e_shoff + i * e_shentsize];
    };

    const uint8_t* shstrtab_hdr = sectionHeader(e_shstrndx);
    uint64_t shstrtab_off = *reinterpret_cast<const uint64_t*>(shstrtab_hdr + 0x18);

    for (uint32_t i = 0; i < e_shnum; i++) {
        const uint8_t* sh = sectionHeader(i);
        uint32_t nameoff    = *reinterpret_cast<const uint32_t*>(sh + 0x00);
        uint64_t addr       = *reinterpret_cast<const uint64_t*>(sh + 0x10);
        uint64_t offset     = *reinterpret_cast<const uint64_t*>(sh + 0x18);
        uint64_t size       = *reinterpret_cast<const uint64_t*>(sh + 0x20);

        const char* name = reinterpret_cast<const char*>(&data[shstrtab_off + nameoff]);
        if (std::string(name) == ".text") {
            return {offset, addr, size, isArm64};
        }
    }
    throw std::out_of_range("Could not find .text");
}

TextSection Patcher::FindTextSection(const std::vector<uint8_t> &data) {
    util::BinFormat format = util::DetectBinFormat(data);

    switch (format) {
        case util::BinFormat::Macho:
            return FindTextMachO(data);
        case util::BinFormat::Elf:
            return FindTextELF(data);
        default:
            throw std::out_of_range("Unknown binary format");
    }
}

ClassifyResult Patcher::ClassifyARM64(const std::vector<uint8_t> &data, uint64_t offset) {
    uint32_t instruction = util::readU32(data, offset);

    if ((instruction & 0x7E000000) == 0x34000000) {
        return {BranchKind::ARM64_CBZ_CBNZ, 4};
    }
    if ((instruction & 0x7E000000) == 0x36000000) {
        return {BranchKind::ARM64_TBZ_TBNZ, 4};
    }
    if ((instruction & 0xFF000000) == 0x54000000) {
        return {BranchKind::ARM64_BCOND, 4};
    }

    return {BranchKind::NONE, 0};
}

ClassifyResult Patcher::ClassifyX86(const std::vector<uint8_t> &data, uint64_t offset) {
    if (offset > data.size()) {
        return {BranchKind::NONE, 0};
    }
    uint8_t b0 = data[offset];

    if (b0 > 0x70 && b0 <= 0x7F) {
        return {BranchKind::X86_SHORT_JCC, 2};
    }
    if (b0 == 0x0F && offset + 1 < data.size()) {
        uint8_t b1 = data[offset + 1];
        if (b1 > 0x80 && b1 < 0x8F) {
            return {BranchKind::X86_NEAR_JCC, 6};
        }
    }

    return {BranchKind::NONE, 0};
}

ClassifyResult Patcher::ClassifyInstruction(const std::vector<uint8_t> &data, uint64_t offset, bool is_arm64) {
    return is_arm64 ? ClassifyARM64(data, offset) : ClassifyX86(data, offset);
}

void Patcher::InvertInstruction(std::vector<uint8_t> &data, uint64_t offset, BranchKind branchKind) {
    switch (branchKind) {
        case BranchKind::ARM64_CBZ_CBNZ:
        case BranchKind::ARM64_TBZ_TBNZ: {
            uint32_t instruction = util::readU32(data, offset);
            util::writeU32(data, offset, instruction ^ 0x01000000);
            break;
        }
        case BranchKind::ARM64_BCOND: {
            uint32_t instruction = util::readU32(data, offset);
            uint32_t cond = (instruction & 0xF) ^ 0x1;
            util::writeU32(data, offset, (instruction & 0xFFFFFFF0) | cond);
            break;
        }
        case BranchKind::X86_SHORT_JCC: {
            if (offset >= data.size()) {
                throw std::out_of_range("Write out of bounds");
            }
            data[offset] ^= 0x01;
            break;
        }
        case BranchKind::X86_NEAR_JCC: {
            if (offset + 1 >= data.size()) {
                throw std::out_of_range("Write out of bounds");
            }
            data[offset + 1] ^= 0x01;
            break;
        }
        default:
            throw std::out_of_range("Unknown branch kind");
    }
}

std::vector<uint8_t> Patcher::FlipBranch(std::vector<uint8_t> data, uint64_t address) {
    TextSection textSection = FindTextSection(data);
    uint64_t fileOffset = textSection.offset + (address - textSection.vaddr);

    ClassifyResult classifyResult = ClassifyInstruction(data, fileOffset, textSection.isArm64);
    if (classifyResult.branchKind == BranchKind::NONE) {
        throw std::out_of_range("No conditional branch at this address");
    }

    InvertInstruction(data, fileOffset, classifyResult.branchKind);
    return data;
}

std::vector<uint8_t> Patcher::NOPRange(std::vector<uint8_t> data, uint64_t address, uint64_t length) {
    TextSection textSection = FindTextSection(data);
    uint64_t fileOffset = textSection.offset + (address - textSection.vaddr);

    if (fileOffset + length > data.size()) {
        throw std::out_of_range("NOP out of bounds");
    }

    if (textSection.isArm64) {
        if (length % 4 != 0) {
            throw std::out_of_range("NOP length must be a multiple of 4 bytes");
        }
        const uint8_t nop[4] = {0x1F, 0x20, 0x03, 0xD5};
        for (uint64_t i = 0; i < length; i += 4) {
            for (int j = 0; j < 4; j++) {
                data[fileOffset + i + j] = nop[j];
            }
        }
    }
    else {
        for (uint64_t i = 0; i < length; i++) {
            data[fileOffset + i] = 0x90;
        }
    }

    return data;
}

std::vector<uint8_t> Patcher::WriteBytes(std::vector<uint8_t> data, uint64_t address, const std::vector<uint8_t>& bytes) {
    TextSection textSection = FindTextSection(data);
    uint64_t fileOffset = textSection.offset + (address - textSection.vaddr);

    if (fileOffset + bytes.size() > data.size()) {
        throw std::out_of_range("Write out of bounds");
    }

    std::memcpy(&data[fileOffset], bytes.data(), bytes.size());
    return data;
}