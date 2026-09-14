//
// Created by Dmitri on 2026-09-06.
//

#include "Disassembly.h"

#include <capstone/capstone.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>

struct ArchitectureMode {
    cs_arch arch;
    cs_mode mode;
};

std::string toLower(const std::string& str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return lowerStr;
}

ArchitectureMode resolveArchitectureMode(const util::ParsedBinary& parsed) {
    if (parsed.format == util::BinFormat::Elf) {
        switch (parsed.elfHeader.e_machine) {
            case 0x3e:
                return {CS_ARCH_X86, CS_MODE_64};
            case 0x03:
                return {CS_ARCH_X86, CS_MODE_32};
            case 0xb7:
                return {CS_ARCH_ARM64, CS_MODE_ARM};
            default:
                throw std::runtime_error("Unknown architecture mode");
        }
    }
    if (parsed.format == util::BinFormat::Macho) {
        switch (parsed.machoHeader.cputype) {
            case 0x01000007:
                return {CS_ARCH_X86, CS_MODE_64};
            case 0x010000c:
                return {CS_ARCH_ARM64, CS_MODE_ARM};
            default:
                throw std::runtime_error("Unknown architecture mode");
        }
    }
    throw std::runtime_error("Cannot resolve architecture mode from format");
}

std::string bytesToHexString(const uint8_t* bytes, size_t length) {
    std::ostringstream ss;
    for (size_t i = 0; i < length; i++) {
        if (i) {
            ss << ' ';
        }
        ss << std::hex << std::setw(2) << std::setfill('0') << int(bytes[i]);
    }
    return ss.str();
}

std::optional<uint64_t> extractDirectTarget(cs_insn* instruction, cs_arch architecture) {
    if (!instruction->detail) {
        return std::nullopt;
    }

    if (architecture == CS_ARCH_X86) {
        cs_x86& x86 = instruction->detail->x86;
        for (int i = 0; i < x86.op_count; i++) {
            if (x86.operands[i].type == X86_OP_IMM) {
                return uint64_t(x86.operands[i].imm);
            }
        }
    }
    else if (architecture == CS_ARCH_ARM64) {
        cs_arm64& arm64 = instruction->detail->arm64;
        for (int i = 0; i < arm64.op_count; i++) {
            if (arm64.operands[i].type == ARM64_OP_IMM) {
                return uint64_t(arm64.operands[i].imm);
            }
        }
    }

    return std::nullopt;
}

InstructionGroup classify(const std::string& mnemonic) {
    std::string m = toLower(mnemonic);

    if (m == "call" || m == "bl" || m == "blr") {
        return InstructionGroup::Call;
    }
    if (m == "ret" || m == "retq") {
        return InstructionGroup::Ret;
    }
    if ((m.size() && m[0] == 'j') || (m.size() >= 2 && m.rfind("b.", 0) == 0) || m == "b" || m == "cbz" || m == "cbnz") {
        return InstructionGroup::Jump;
    }
    if (m.rfind("cmp", 0) == 0 || m == "test") {
        return InstructionGroup::Cmp;
    }

    return InstructionGroup::Normal;
}

const util::Symbol* resolveSymbol(uint64_t address, const std::vector<util::Symbol>& symbols) {
    if (symbols.empty()) {
        return nullptr;
    }

    int lo = 0, hi = int(symbols.size()) - 1, found = -1;
    while (lo <= hi) {
        int mid = (lo + hi)/2;
        if (symbols[mid].addr <= address) {
            found = mid;
            lo = mid + 1;
        }
        else {
            hi = mid - 1;
        }
    }

    if (found == -1) {
        return nullptr;
    }

    const util::Symbol& sym = symbols[found];
    if (sym.size > 0 && address > sym.addr + sym.size) {
        return nullptr;
    }
    return &sym;
}

std::string labelForAddress(uint64_t address, const std::vector<util::Symbol>& symbols) {
    const util::Symbol* sym = resolveSymbol(address, symbols);
    if (!sym) {
        std::ostringstream ss;
        ss << "sub_" << std::hex << address;
        return ss.str();
    }

    uint64_t delta = address - sym->addr;
    if (delta == 0) {
        return sym->name;
    }
    std::ostringstream ss;
    ss << sym->name << "+0x" << std::hex << delta;
    return ss.str();
}

std::vector<Function> buildFunctions(const std::vector<Instruction>& instructions, const std::vector<util::Symbol>& symbols, uint64_t textBase, uint64_t textSize) {

    std::vector<uint64_t> bounds;
    for (const util::Symbol& sym : symbols) {
        bounds.push_back(sym.addr);
    }
    if (bounds.empty() || bounds.front() != textBase) {
        bounds.insert(bounds.begin(), textBase);
    }
    bounds.push_back(textBase + textSize);

    std::vector<Function> functions;
    for (size_t i = 0; i < bounds.size(); i++) {
        uint64_t start = bounds[i];
        uint64_t end = bounds[i + 1];

        if (start >= end) {
            continue;
        }

        Function func;
        func.start = start;
        func.end = end;
        auto symIt = std::find_if(symbols.begin(), symbols.end(), [&](const util::Symbol& sym) {
            return sym.addr == start;
        });

        if (symIt != symbols.end()) {
            func.name = symIt->name;
        }
        else {
            std::ostringstream ss;
            ss << "sub_" << std::hex << start;
            func.name = ss.str();
        }

        functions.push_back(func);
    }

    size_t funcIndex = 0;
    for (size_t i = 0; i < instructions.size(); i++) {
        while (funcIndex + 1 < functions.size() && instructions[i].address >= functions[funcIndex].end) {
            funcIndex++;
        }
        if (funcIndex < functions.size()) {
            functions[funcIndex].instructionIndices.push_back(funcIndex);
        }
    }
    return functions;
}

DisassemblyResult disassemble(const util::ParsedBinary& parsed) {

    ArchitectureMode architecture = resolveArchitectureMode(parsed);
    csh handle;
    if (cs_open(architecture.arch, architecture.mode, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Cannot open disassembler handle");
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insns = nullptr;

    size_t count = cs_disasm(handle, parsed.text.bytes.data(), parsed.text.bytes.size(), parsed.text.baseAddr, 0, &insns);

    DisassemblyResult disassemblyResult;
    disassemblyResult.instructions.reserve(count);

    for (size_t i = 0; i < count; i++) {
        cs_insn& insn = insns[i];
        InstructionGroup instructionGroup = classify(insn.mnemonic);

        std::optional<uint64_t> target;
        if (instructionGroup == InstructionGroup::Jump || instructionGroup == InstructionGroup::Call) {
            target = extractDirectTarget(&insn, architecture.arch);
        }

        Instruction out;
        out.address     = insn.address;
        out.bytes       = bytesToHexString(insn.bytes, insn.size);
        out.operands    = insn.op_str;
        out.size        = insn.size;
        out.group       = instructionGroup;
        out.target      = target;
        out.targetName  = target ? labelForAddress(target.value(), parsed.symbols) : "";

        disassemblyResult.instructions.push_back(out);
    }

    if (insns) {
        cs_free(insns, count);
    }
    cs_close(&handle);

    for (const Instruction& instruction : disassemblyResult.instructions) {
        if (instruction.target) {
            disassemblyResult.xrefs[*instruction.target].push_back(instruction.address);
        }
    }

    disassemblyResult.functions = buildFunctions(disassemblyResult.instructions, parsed.symbols, parsed.text.baseAddr, parsed.text.size);
    return disassemblyResult;
}