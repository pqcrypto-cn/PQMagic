set(SOURCE_FILES_GF_${SVARIANT_UPPER}_REF
    ${GFX_DIR}/fp2.c
    ${GFX_DIR}/mp.c
    fp_p765.c
)

add_library(${LIB_GF_${SVARIANT_UPPER}} ${SOURCE_FILES_GF_${SVARIANT_UPPER}_REF})
target_include_directories(${LIB_GF_${SVARIANT_UPPER}} PRIVATE ${INC_COMMON} ${INC_PRECOMP_${SVARIANT_UPPER}} ${INC_GF} include ${PROJECT_SOURCE_DIR}/include)
target_compile_options(${LIB_GF_${SVARIANT_UPPER}} PRIVATE ${C_OPT_FLAGS})

add_subdirectory(test)