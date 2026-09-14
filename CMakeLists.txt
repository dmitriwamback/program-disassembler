cmake_minimum_required(VERSION 3.16)
project(disassembler)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

add_executable(disassembler main.cpp
        src/elf/ELF.cpp
        src/elf/ELF.h
        src/macho/MachO.cpp
        src/macho/MachO.h
        src/low_level/Binary.cpp
        src/low_level/Binary.h
        src/low_level/Disassembly.cpp
        src/low_level/Disassembly.h
        src/low_level/Patcher.cpp
        src/low_level/Patcher.h
        src/display/PatchDialog.cpp
        src/display/PatchDialog.h
        src/display/MainWindow.cpp
        src/display/MainWindow.h
        src/util/format.h
        src/util/binary_types.h
        src/util/read_bytes.h
        src/util/write_bytes.h)

target_include_directories(disassembler PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CAPSTONE_INCLUDE_DIRS})

target_link_libraries(disassembler PRIVATE
        Qt6::Widgets
        ${CAPSTONE_LIBRARIES})

target_link_directories(disassembler PRIVATE ${CAPSTONE_LIBRARY_DIRS})