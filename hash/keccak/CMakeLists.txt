cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# include path
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT})

# add source code.
set(FIPS202_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/fips202.c
)

# Set fips202 object.
add_library(fips202 OBJECT ${FIPS202_SOURCES})
