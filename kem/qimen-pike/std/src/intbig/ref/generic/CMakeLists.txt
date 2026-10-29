set(SOURCE_FILES_INTBIG_GENERIC_REF
    intbig.c
)

add_library(${LIB_INTBIG} ${SOURCE_FILES_INTBIG_GENERIC_REF})
target_include_directories(${LIB_INTBIG} PRIVATE common ${INC_PUBLIC} ${INC_COMMON} include gmp)
# target_link_libraries(${LIB_INTBIG} PRIVATE ${GMP} pike_common_sys lib_precomp lib_hd lib_ec lib_gf)
target_compile_options(${LIB_INTBIG} PRIVATE ${C_OPT_FLAGS})

add_subdirectory(test)
