# SPDX-License-Identifier: Apache-2.0

# AddressSanitizer
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)

# LeakSanitizer
set(CMAKE_C_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during LeakSanitizer builds."
    FORCE)

# MemorySanitizer
set(CMAKE_C_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during MemorySanitizer builds."
    FORCE)

# UndefinedBehaviour
set(CMAKE_C_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C compiler during UndefinedBehaviourSanitizer builds."
    FORCE)

set(CMAKE_C_FLAGS_COVERAGE
    "-fprofile-arcs -ftest-coverage"
    CACHE STRING "Flags used by the C compiler during Coverage builds."
    FORCE)

set(CMAKE_C_FLAGS_PERF
    "-ggdb"
    CACHE STRING "Flags used for profiling with perf or pprof."
    FORCE)

set(CMAKE_C_FLAGS_GPROF
    "-g -pg"
    CACHE STRING "Flags used for profiling with gprof."
    FORCE)