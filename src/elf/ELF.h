//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_ELF_H
#define DISASSEMBLER_ELF_H
#include "../util/binary_types.h"


class ELF {
public:
    static util::ParsedBinary ParseElf(const std::vector<uint8_t>& buffer);
};


#endif //DISASSEMBLER_ELF_H
