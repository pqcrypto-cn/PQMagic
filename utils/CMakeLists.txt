cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT}/include)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# add randombytes.c as source.
file(GLOB UTILS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/randombytes.c)

# Set randombytes object.
add_library(randombytes OBJECT ${UTILS_SOURCES})

# Set header for using randombytes.
target_include_directories(randombytes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
