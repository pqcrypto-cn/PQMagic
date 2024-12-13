cmake_minimum_required(VERSION 3.10)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# add randombytes.c as source.
file(GLOB UTILS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/randombytes.c)

# add static lib for randombytes.
add_library(randombytes STATIC ${UTILS_SOURCES})

# Set header for using randombytes.
target_include_directories(randombytes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
