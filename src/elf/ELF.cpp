//
// Created by Dmitri on 2026-09-06.
//

#include "ELF.h"

#include "../util/read_bytes.h"

constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint32_t STT_FUNC = 2;

util::ElfHeaderInfo ParseElfHeader(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 0x40) {
        throw std::out_of_range("ELF: File too small");
    }
    if (util::readU32LE(buffer, 0) != 0x464C457F) {
        throw std::out_of_range("ELF: File is not an ELF");
    }

    uint8_t eiClass = util::readU8(buffer, 4);
    uint8_t eiData = util::readU8(buffer, 5);

    bool is64 = eiClass == 2;
    bool le = eiData == 1;

    if (!is64) {
        throw std::out_of_range("64-bit ELF supported only");
    }
    if (!le) {
        throw std::out_of_range("Only little-endian ELF is supported");
    }

    util::ElfHeaderInfo header;
    header.is64 = is64;
    header.le = le;
    header.e_type = util::readU16LE(buffer, 0x10);
    header.e_machine = util::readU16LE(buffer, 0x12);
    header.e_entry = util::readU64LE(buffer, 0x18);
    header.e_phoff = util::readU64LE(buffer, 0x20);
    header.e_shoff = util::readU64LE(buffer, 0x28);
    header.e_shentsize = util::readU16LE(buffer, 0x3a);
    header.e_shnum = util::readU16LE(buffer, 0x3c);
    header.e_shstrndx = util::readU16LE(buffer, 0x3e);

    return header;
}

std::vector<util::Section> ParseSectionHeaders(const std::vector<uint8_t>& buffer, const util::ElfHeaderInfo& header) {
    std::vector<util::Section> sections;
    sections.reserve(header.e_shnum);

    std::vector<uint32_t> nameOffsets(header.e_shnum);

    for (int i = 0; i < header.e_shnum; i++) {
        uint64_t base = header.e_shoff + static_cast<uint64_t>(i) * header.e_shentsize;

        util::Section section;
        nameOffsets[i]  = util::readU32LE(buffer, base + 0x00);
        section.type    = util::readU32LE(buffer, base + 0x04);
        section.flags   = util::readU64LE(buffer, base + 0x08);
        section.addr    = util::readU64LE(buffer, base + 0x10);
        section.offset  = util::readU64LE(buffer, base + 0x18);
        section.size    = util::readU64LE(buffer, base + 0x20);
        section.link    = util::readU32LE(buffer, base + 0x28);
        section.info    = util::readU32LE(buffer, base + 0x2c);
        section.entsize = util::readU64LE(buffer, base + 0x38);

        sections.push_back(std::move(section));
    }

    if (header.e_shstrndx < sections.size()) {
        uint64_t shstrtabOff = sections[header.e_shstrndx].offset;
        for (size_t i = 0; i < sections.size(); i++) {
            sections[i].name = util::readCString(buffer, shstrtabOff + nameOffsets[i]);
        }
    }
    return sections;
}

std::vector<util::Symbol> ParseSymbols(const std::vector<uint8_t>& buffer, const util::ElfHeaderInfo& header, const std::vector<util::Section>& sections) {
	auto it = std::find_if(sections.begin(), sections.end(), [](const util::Section& s) { return s.type == SHT_SYMTAB; });
	if (it == sections.end()) return {};
	const util::Section& symtabSec = *it;

	if (symtabSec.link >= sections.size()) return {};
	const util::Section& strtabSec = sections[symtabSec.link];

	uint64_t entrySize = symtabSec.entsize ? symtabSec.entsize : 24;
	uint64_t count = symtabSec.size / entrySize;

	std::vector<util::Symbol> symbols;
	for (uint64_t i = 0; i < count; i++) {
		uint64_t base		= symtabSec.offset + i * entrySize;
		uint32_t st_name	= util::readU32LE(buffer, base + 0x00);
		uint8_t st_info		= util::readU8(buffer, base + 0x04);
		uint64_t st_value	= util::readU64LE(buffer, base + 0x08);
		uint64_t st_size	= util::readU64LE(buffer, base + 0x10);

		uint8_t type = st_info & 0xf;
		if (type != STT_FUNC || st_value == 0) continue;

		util::Symbol sym;
		sym.name = util::readCString(buffer, strtabSec.offset + st_name);
		sym.addr = st_value;
		sym.size = st_size;
		symbols.push_back(std::move(sym));
	}

	std::sort(symbols.begin(), symbols.end(), [](const util::Symbol& a, const util::Symbol& b) { return a.addr < b.addr; });
	return symbols;
}

std::vector<std::string> ParseDynsymNames(const std::vector<uint8_t>& buffer, const util::ElfHeaderInfo& header, const std::vector<util::Section>& sections) {

	auto it = std::find_if(sections.begin(), sections.end(), [](const util::Section& s) { return s.type == SHT_DYNSYM; });
	if (it == sections.end()) {
		return {};
	}

	const util::Section& dynsymSec = *it;
	if (dynsymSec.link >= sections.size()) {
		return {};
	}

	const util::Section& strtabSec = sections[dynsymSec.link];
	uint64_t entrySize = dynsymSec.entsize ? dynsymSec.entsize : 24;
	uint64_t count = dynsymSec.size / entrySize;

	std::vector<std::string> names;
	names.reserve(count);

	for (uint64_t i = 0; i < count; i++) {
		uint64_t base = dynsymSec.offset + i * entrySize;
		uint32_t st_name = util::readU32LE(buffer, base + 0x00);
		names.push_back(st_name ? util::readCString(buffer, strtabSec.offset + st_name) : "");
	}
	return names;
}


std::vector<util::Symbol> ParsePltImports(const std::vector<uint8_t>& buffer, const util::ElfHeaderInfo& header, const std::vector<util::Section>& sections) {

	auto relaIt = std::find_if(sections.begin(), sections.end(), [](const util::Section& s) { return s.name == ".rela.plt"; });
	if (relaIt == sections.end()) {
		return {};
	}

	const util::Section& relaPltSec = *relaIt;
	std::vector<std::string> dynsymNames = ParseDynsymNames(buffer, header, sections);

	uint64_t relaEntrySize = relaPltSec.entsize ? relaPltSec.entsize : 24;
	uint64_t relocCount = relaPltSec.size / relaEntrySize;

	std::vector<uint32_t> symIndices;
	symIndices.reserve(relocCount);
	for (uint64_t i = 0; i < relocCount; i++) {
		uint64_t base = relaPltSec.offset + i * relaEntrySize;
		uint64_t r_info = util::readU64LE(buffer, base + 0x08);
		symIndices.push_back(uint32_t(r_info >> 32));
	}

	auto pltSecIt = std::find_if(sections.begin(), sections.end(), [](const util::Section& s) { return s.name == ".plt.sec"; });

	if (pltSecIt == sections.end()) {
		pltSecIt = std::find_if(sections.begin(), sections.end(), [](const util::Section& s) { return s.name == ".plt"; });
	}
	if (pltSecIt == sections.end()) {
		return {};
	}

	const util::Section& pltSec = *pltSecIt;
	constexpr uint64_t PLT_ENTRY_SIZE = 16;

	uint64_t totalEntries = pltSec.size / PLT_ENTRY_SIZE;
	uint64_t startIndex = (totalEntries == symIndices.size() + 1) ? 1 : 0;
	std::vector<util::Symbol> imports;

	for (size_t i = 0; i < symIndices.size(); i++) {

		if (symIndices[i] >= dynsymNames.size()) continue;

		const std::string& name = dynsymNames[symIndices[i]];
		if (name.empty()) continue;

		util::Symbol sym;
		sym.name = name;
		sym.addr = pltSec.addr + (startIndex + i) * PLT_ENTRY_SIZE;
		sym.size = PLT_ENTRY_SIZE;
		sym.external = true;
		imports.push_back(std::move(sym));
	}
	return imports;
}

util::ParsedBinary ELF::ParseElf(const std::vector<uint8_t>& buffer) {
	util::ParsedBinary result;
	result.format = util::BinFormat::Elf;
	result.fileBytes = buffer;

	result.elfHeader = ParseElfHeader(buffer);
	result.sections = ParseSectionHeaders(buffer, result.elfHeader);

	std::vector<util::Symbol> localSymbols = ParseSymbols(buffer, result.elfHeader, result.sections);
	std::vector<util::Symbol> pltImports = ParsePltImports(buffer, result.elfHeader, result.sections);

	result.symbols = localSymbols;
	result.symbols.insert(result.symbols.end(), pltImports.begin(), pltImports.end());
	std::sort(result.symbols.begin(), result.symbols.end(), [](const util::Symbol& a, const util::Symbol& b) { return a.addr < b.addr; });

	auto textIt = std::find_if(result.sections.begin(), result.sections.end(), [](const util::Section& s) { return s.name == ".text"; });
	if (textIt == result.sections.end()) {
		throw std::runtime_error("No .text section found");
	}

	if (textIt->offset + textIt->size > buffer.size()) {
		throw std::runtime_error(".text section extends past end of file");
	}

	result.text.bytes.assign(buffer.begin() + textIt->offset, buffer.begin() + textIt->offset + textIt->size);
	result.text.baseAddr = textIt->addr;
	result.text.fileOffset = textIt->offset;
	result.text.size = textIt->size;

	return result;
}