set(PIKEX_COMPRESSED_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_library(${LIB_PIKE_${SVARIANT_UPPER}}_compressed ${PIKEX_COMPRESSED_DIR}/pike_compressed.c)
target_include_directories(${LIB_PIKE_${SVARIANT_UPPER}}_compressed PRIVATE
    ${PIKEX_COMPRESSED_DIR}/include
    ${INC_GF} ${INC_COMMON} ${INC_PRECOMP_${SVARIANT_UPPER}}
    ${INC_HD} ${INC_EC} ${INC_INTBIG} ${INC_PUBLIC}
    ${INC_QUATERNION} ${INC_KLPT} ${INC_ID2ISO}
    ${INC_PIKE} ${INC_PIKE_${SVARIANT_UPPER}})
target_link_libraries(${LIB_PIKE_${SVARIANT_UPPER}}_compressed PRIVATE
    ${LIB_EC_${SVARIANT_UPPER}} ${LIB_HD_${SVARIANT_UPPER}}
    ${LIB_INTBIG} ${LIB_KLPT_${SVARIANT_UPPER}}
    ${LIB_QUATERNION} ${LIB_ID2ISO_${SVARIANT_UPPER}})
target_compile_options(${LIB_PIKE_${SVARIANT_UPPER}}_compressed PRIVATE ${C_OPT_FLAGS})
target_compile_definitions(${LIB_PIKE_${SVARIANT_UPPER}}_compressed PUBLIC PIKE_COMPRESSED_SHARED_SECRET_BYTES=64)

add_subdirectory(test)
