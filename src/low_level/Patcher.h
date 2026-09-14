//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_PATCHER_H
#define DISASSEMBLER_PATCHER_H
#include <cstdint>
#include <vector>

struct TextSection {
    uint64_t offset;
    uint64_t size;
    uint64_t vaddr;
    bool isArm64;
};

enum class BranchKind {
    NONE, ARM64_CBZ_CBNZ, ARM64_TBZ_TBNZ, ARM64_BCOND, X86_SHORT_JCC, X86_NEAR_JCC
};

struct ClassifyResult {
    BranchKind branchKind;
    uint64_t instructionLength;
};

class Patcher {
public:
    static std::vector<uint8_t> FlipBranch(std::vector<uint8_t> data, uint64_t address);
    static std::vector<uint8_t> NOPRange(std::vector<uint8_t> data, uint64_t address, uint64_t length);
    static std::vector<uint8_t> WriteBytes(std::vector<uint8_t> data, uint64_t address, const std::vector<uint8_t>& bytes);

    static void InvertInstruction(std::vector<uint8_t>& data, uint64_t offset, BranchKind branchKind);

    static TextSection FindTextMachO(const std::vector<uint8_t>& data);
    static TextSection FindTextELF(const std::vector<uint8_t>& data);
    static TextSection FindTextSection(const std::vector<uint8_t>& data);

    static ClassifyResult ClassifyARM64(const std::vector<uint8_t>& data, uint64_t offset);
    static ClassifyResult ClassifyX86(const std::vector<uint8_t>& data, uint64_t offset);
    static ClassifyResult ClassifyInstruction(const std::vector<uint8_t>& data, uint64_t offset, bool is_arm64);
};


#endif //DISASSEMBLER_PATCHER_H
