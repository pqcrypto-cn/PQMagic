cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# include path
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/x86-64/include ${CMAKE_PROJECT_ROOT})

# add source code.
set(SM3_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/x86-64/sm3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sm3_extended.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mgf_sm3.c
)

# Set sm3 object.
add_library(sm3 OBJECT ${SM3_SOURCES})
