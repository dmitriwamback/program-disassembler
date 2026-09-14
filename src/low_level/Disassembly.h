//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_DISASSEMBLY_H
#define DISASSEMBLER_DISASSEMBLY_H
#include <cstdint>
#include <string>
#include <optional>
#include <unordered_map>
#include <vector>

#include "../util/binary_types.h"

enum class InstructionGroup {
    Call, Ret, Jump, Cmp, Normal
};

struct Instruction {
    uint64_t address = 0;
    std::string bytes;
    std::string mnemonic;
    std::string operands;
    uint32_t size = 0;
    InstructionGroup group = InstructionGroup::Normal;
    std::optional<uint64_t> target;
    std::string targetName;
};

struct Function {
    std::string name;
    uint64_t start;
    uint64_t end;
    std::vector<size_t> instructionIndices;
};

struct DisassemblyResult {
    std::vector<Instruction> instructions;
    std::unordered_map<uint64_t, std::vector<uint64_t>> xrefs;
    std::vector<Function> functions;
};

class Disassembly {
public:
    static const util::Symbol *ResolveSymbol(uint64_t address, const std::vector<util::Symbol> &symbols);
    static std::string LabelForAddress(uint64_t address, const std::vector<util::Symbol>& symbols);
    static InstructionGroup Classify(const std::string& mnemonic);
    static DisassemblyResult Disassemble(const util::ParsedBinary& parsed);
    static std::vector<Function> BuildFunctions(const std::vector<Instruction>& instructions, const std::vector<util::Symbol>& symbols, uint64_t textBase, uint64_t textSize);
};


#endif //DISASSEMBLER_DISASSEMBLY_H
