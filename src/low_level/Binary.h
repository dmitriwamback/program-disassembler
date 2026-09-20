//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_BINARY_H
#define DISASSEMBLER_BINARY_H
#include "../util/binary_types.h"


class Binary {
public:
    static util::ParsedBinary ParseBinary(const std::vector<uint8_t>& buffer);
    static util::ParsedBinary Reslice(const util::ParsedBinary& parsed, const std::vector<uint8_t>& fullBytes);
};


#endif //DISASSEMBLER_BINARY_H
