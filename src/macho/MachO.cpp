//
// Created by Dmitri on 2026-09-06.
//

#include "MachO.h"

#include "../util/read_bytes.h"

constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_SYMTAB = 0x02;
constexpr uint32_t LC_DYSYMTAB = 0x0b;

constexpr uint8_t N_STAB = 0xe0;
constexpr uint8_t N_TYPE = 0x0e;
constexpr uint8_t N_SECT = 0x0e;

constexpr uint32_t INDIRECT_Symbol_LOCAL = 0x80000000;
constexpr uint32_t INDIRECT_Symbol_ABS = 0x40000000;

constexpr uint32_t Section_TYPE_MASK = 0xff;
constexpr uint32_t S_Symbol_STUBS = 0x08;

struct SymtabCmd {
	uint32_t symoff, nsyms, stroff, strsize;
};
struct DysymtabCmd {
	uint32_t indirectsymoff, nindirectsyms;
};

struct RawSym {
	bool valid = false;
	std::string name;
	uint8_t n_type = 0;
	uint8_t n_sect = 0;
	uint64_t n_value = 0;
};

util::MachoHeaderInfo ParseMachoHeader(const std::vector<uint8_t>& buffer) {
	
	if (buffer.size() < 32) {
		throw std::runtime_error("File too small to be Mach-O");
	}
	uint32_t magicBE = uint32_t(buffer[0]) << 24 | uint32_t(buffer[1]) << 16 | uint32_t(buffer[2]) << 8 | buffer[3];

	bool le;
	if (magicBE == 0xcffaedfe) {
		le = true;
	}
	else if (magicBE == 0xfeedfacf) {
		le = false;
	}
	else if (magicBE == 0xcefaedfe || magicBE == 0xfeedface) {
		throw std::runtime_error("32-bit Mach-O not supported yet -- only 64-bit is implemented");
	}
	else {
		throw std::runtime_error("Unrecognized Mach-O magic");
	}

	util::MachoHeaderInfo header;
	header.magic = magicBE;
	header.le = le;
	header.cputype = util::readU32(buffer, 0x04, le);
	header.cpusubtype = util::readU32(buffer, 0x08, le);
	header.filetype = util::readU32(buffer, 0x0c, le);
	header.ncmds = util::readU32(buffer, 0x10, le);
	header.sizeofcmds = util::readU32(buffer, 0x14, le);
	header.flags = util::readU32(buffer, 0x18, le);
	header.headerSize = 32;
	return header;
}

std::vector<util::Section> ParseMachoSections(const std::vector<uint8_t>& buffer, const util::MachoHeaderInfo& header) {
	std::vector<util::Section> sections;
	uint64_t offset = header.headerSize;

	for (uint32_t i = 0; i < header.ncmds; i++) {
		uint32_t cmd = util::readU32(buffer, offset, header.le);
		uint32_t cmdsize = util::readU32(buffer, offset + 4, header.le);

		if (cmd == LC_SEGMENT_64) {
			std::string segname = util::readCString(buffer, offset + 8, 16);
			uint32_t nsects = util::readU32(buffer, offset + 64, header.le);
			uint64_t sectOff = offset + 72;

			for (uint32_t s = 0; s < nsects; s++) {
				util::Section sec;
				sec.name = util::readCString(buffer, sectOff, 16);
				std::string secSeg = util::readCString(buffer, sectOff + 16, 16);
				sec.segment = secSeg.empty() ? segname : secSeg;
				sec.addr = util::readU64(buffer, sectOff + 32, header.le);
				sec.size = util::readU64(buffer, sectOff + 40, header.le);
				sec.offset = util::readU32(buffer, sectOff + 48, header.le);
				sec.flags = util::readU32(buffer, sectOff + 64, header.le);
				sec.reserved1 = util::readU32(buffer, sectOff + 68, header.le);
				sec.reserved2 = util::readU32(buffer, sectOff + 72, header.le);
				sections.push_back(std::move(sec));
				sectOff += 80;
			}
		}
		offset += cmdsize;
	}
	return sections;
}

std::optional<SymtabCmd> findSymtabCommand(const std::vector<uint8_t>& buffer, const util::MachoHeaderInfo& header) {
	uint64_t offset = header.headerSize;

	for (uint32_t i = 0; i < header.ncmds; i++) {
		uint32_t cmd = util::readU32(buffer, offset, header.le);
		uint32_t cmdsize = util::readU32(buffer, offset + 4, header.le);

		if (cmd == LC_SYMTAB) {
			SymtabCmd s{};
			s.symoff = util::readU32(buffer, offset + 8, header.le);
			s.nsyms = util::readU32(buffer, offset + 12, header.le);
			s.stroff = util::readU32(buffer, offset + 16, header.le);
			s.strsize = util::readU32(buffer, offset + 20, header.le);
			return s;
		}
		offset += cmdsize;
	}
	return std::nullopt;
}

std::optional<DysymtabCmd> findDysymtabCommand(const std::vector<uint8_t>& buffer, const util::MachoHeaderInfo& header) {
	uint64_t offset = header.headerSize;

	for (uint32_t i = 0; i < header.ncmds; i++) {
		uint32_t cmd = util::readU32(buffer, offset, header.le);
		uint32_t cmdsize = util::readU32(buffer, offset + 4, header.le);

		if (cmd == LC_DYSYMTAB) {
			DysymtabCmd d{};
			d.indirectsymoff = util::readU32(buffer, offset + 56, header.le);
			d.nindirectsyms = util::readU32(buffer, offset + 60, header.le);
			return d;
		}
		offset += cmdsize;
	}
	return std::nullopt;
}

std::vector<RawSym> ParseAllSymbols(const std::vector<uint8_t>& buffer, const util::MachoHeaderInfo& header, const SymtabCmd& symtab) {
	constexpr uint64_t ENTRY_SIZE = 16;
	std::vector<RawSym> syms;
	syms.reserve(symtab.nsyms);

	for (uint32_t i = 0; i < symtab.nsyms; i++) {
		uint64_t base = symtab.symoff + uint64_t(i) * ENTRY_SIZE;
		uint32_t n_strx = util::readU32(buffer, base + 0x00, header.le);
		uint8_t n_type = util::readU8(buffer, base + 0x04);
		uint8_t n_sect = util::readU8(buffer, base + 0x05);
		uint64_t n_value = util::readU64(buffer, base + 0x08, header.le);

		RawSym sym;
		if ((n_type & N_STAB) || n_strx == 0) {
			syms.push_back(sym);
			continue;
		}
		sym.valid = true;
		sym.name = util::readCString(buffer, symtab.stroff + n_strx, symtab.strsize > n_strx ? symtab.strsize - n_strx : 0);
		sym.n_type = n_type;
		sym.n_sect = n_sect;
		sym.n_value = n_value;
		syms.push_back(std::move(sym));
	}
	return syms;
}

std::vector<util::Symbol> ParseTextSymbols(const std::vector<RawSym>& allSyms, const std::vector<util::Section>& sections) {
	int textOrdinal = -1;
	for (size_t i = 0; i < sections.size(); i++) {
		if (sections[i].name == "__text" && sections[i].segment == "__TEXT") {
			textOrdinal = int(i) + 1;
			break;
		}
	}
	if (textOrdinal < 0) return {};
	const util::Section& section = sections[textOrdinal - 1];

	std::vector<util::Symbol> raw;
	for (const RawSym& s : allSyms) {
		if (!s.valid) {
			continue;
		}
		if ((s.n_type & N_TYPE) != N_SECT) {
			continue;
		}
		if (s.n_sect != textOrdinal) {
			continue;
		}
		util::Symbol sym;
		sym.name = s.name;
		sym.addr = s.n_value;
		raw.push_back(std::move(sym));
	}

	std::sort(raw.begin(), raw.end(), [](const util::Symbol& a, const util::Symbol& b) { return a.addr < b.addr; });
	uint64_t textEnd = section.addr + section.size;

	std::vector<util::Symbol> out;
	out.reserve(raw.size());

	for (size_t i = 0; i < raw.size(); i++) {
		uint64_t nextAddr = (i + 1 < raw.size()) ? raw[i + 1].addr : textEnd;
		util::Symbol sym = raw[i];
		sym.size = nextAddr > sym.addr ? nextAddr - sym.addr : 0;
		out.push_back(std::move(sym));
	}
	return out;
}


std::vector<util::Symbol> ParseStubSymbols(const std::vector<uint8_t>& buffer, const util::MachoHeaderInfo& header, const std::vector<util::Section>& sections, const std::vector<RawSym>& allSyms, const std::optional<DysymtabCmd>& dysymtab) {
	if (!dysymtab) return {};

	std::vector<uint32_t> indirect(dysymtab->nindirectsyms);
	for (uint32_t i = 0; i < dysymtab->nindirectsyms; i++) {
		indirect[i] = util::readU32(buffer, dysymtab->indirectsymoff + uint64_t(i) * 4, header.le);
	}

	std::vector<util::Symbol> results;
	for (const util::Section& stubSec : sections) {

		if ((stubSec.flags & Section_TYPE_MASK) != S_Symbol_STUBS) {
			continue;
		}
		if (stubSec.reserved2 == 0) {
			continue;
		}

		uint64_t count = stubSec.size / stubSec.reserved2;

		for (uint64_t i = 0; i < count; i++) {
			uint64_t indirectIdx = stubSec.reserved1 + i;
			if (indirectIdx >= indirect.size()) {
				continue;
			}

			uint32_t idx = indirect[indirectIdx];
			if (idx == INDIRECT_Symbol_LOCAL || idx == INDIRECT_Symbol_ABS) {
				continue;
			}
			if (idx >= allSyms.size() || !allSyms[idx].valid) {
				continue;
			}

			util::Symbol sym;
			sym.name = allSyms[idx].name;
			sym.addr = stubSec.addr + i * stubSec.reserved2;
			sym.size = stubSec.reserved2;
			sym.external = true;
			results.push_back(std::move(sym));
		}
	}
	return results;
}

util::ParsedBinary MachO::ParseMachO(const std::vector<uint8_t>& buffer) {
	util::ParsedBinary result;
	result.format = util::BinFormat::Macho;
	result.fileBytes = buffer;

	result.machoHeader = ParseMachoHeader(buffer);
	result.sections = ParseMachoSections(buffer, result.machoHeader);

	std::vector<util::Symbol> functionSymbols;
	std::vector<util::Symbol> stubSymbols;

	if (auto symtab = findSymtabCommand(buffer, result.machoHeader)) {

		std::vector<RawSym> allSyms = ParseAllSymbols(buffer, result.machoHeader, *symtab);
		functionSymbols = ParseTextSymbols(allSyms, result.sections);

		auto dysymtab = findDysymtabCommand(buffer, result.machoHeader);
		stubSymbols = ParseStubSymbols(buffer, result.machoHeader, result.sections, allSyms, dysymtab);
	}

	result.symbols = functionSymbols;
	result.symbols.insert(result.symbols.end(), stubSymbols.begin(), stubSymbols.end());
	std::sort(result.symbols.begin(), result.symbols.end(), [](const util::Symbol& a, const util::Symbol& b) { return a.addr < b.addr; });

	auto textIt = std::find_if(result.sections.begin(), result.sections.end(), [](const util::Section& s) { return s.name == "__text"; });

	if (textIt == result.sections.end()) {
		throw std::runtime_error("No __text section found");
	}
	if (textIt->offset + textIt->size > buffer.size()) {
		throw std::runtime_error("__text section extends past end of file");
	}

	result.text.bytes.assign(buffer.begin() + textIt->offset, buffer.begin() + textIt->offset + textIt->size);
	result.text.baseAddr = textIt->addr;
	result.text.fileOffset = textIt->offset;
	result.text.size = textIt->size;

	return result;
}