set(SOURCE_FILES_COMMON_SYS 
    randombytes_system.c 
    aes_c.c 
    fips202.c 
    pike_hash.c
    # mem.c
    tools.c
)

add_library(pike_common_sys ${SOURCE_FILES_COMMON_SYS})
target_include_directories(pike_common_sys PRIVATE include ../../include)
target_compile_options(pike_common_sys PUBLIC ${C_OPT_FLAGS})

set(SOURCE_FILES_COMMON_TEST 
    randombytes_ctrdrbg.c 
    aes_c.c 
    fips202.c 
    pike_hash.c
    # mem.c
    tools.c
)

add_library(pike_common_test ${SOURCE_FILES_COMMON_TEST})
target_include_directories(pike_common_test PRIVATE include ../include)
target_compile_options(pike_common_test PUBLIC ${C_OPT_FLAGS})

if (ENABLE_CT_TESTING)
    target_compile_definitions(pike_common_sys PUBLIC ENABLE_CT_TESTING)
    target_compile_definitions(pike_common_test PUBLIC ENABLE_CT_TESTING)
endif()
