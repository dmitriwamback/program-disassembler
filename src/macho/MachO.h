//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_MACHO_H
#define DISASSEMBLER_MACHO_H
#include "../util/binary_types.h"


class MachO {
public:
    static util::ParsedBinary ParseMachO(const std::vector<uint8_t>& buffer);
};


#endif //DISASSEMBLER_MACHO_H
