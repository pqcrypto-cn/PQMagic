cmake_minimum_required(VERSION 3.16)
project(pqmagic_provider C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

set(PQMAGIC_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../include" CACHE PATH "Path to PQMagic headers")
set(PQMAGIC_LIB "" CACHE FILEPATH "Path to libpqmagic_std.a or libpqmagic_std.so")

if(NOT EXISTS "${PQMAGIC_INCLUDE_DIR}/pqmagic_api.h")
    message(FATAL_ERROR "pqmagic_api.h not found under PQMAGIC_INCLUDE_DIR=${PQMAGIC_INCLUDE_DIR}")
endif()

if(PQMAGIC_LIB STREQUAL "")
    message(FATAL_ERROR "Please set -DPQMAGIC_LIB=/abs/path/to/libpqmagic_std.a (or .so)")
endif()

if(NOT EXISTS "${PQMAGIC_LIB}")
    message(FATAL_ERROR "PQMAGIC_LIB not found: ${PQMAGIC_LIB}")
endif()

add_library(pqmagicprov MODULE
    src/provider.c
)

target_include_directories(pqmagicprov PRIVATE
    "${PQMAGIC_INCLUDE_DIR}"
)

target_link_libraries(pqmagicprov PRIVATE
    OpenSSL::Crypto
    "${PQMAGIC_LIB}"
)

set_target_properties(pqmagicprov PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pqmagicprov"
)

install(TARGETS pqmagicprov
    LIBRARY DESTINATION lib/ossl-modules
)
