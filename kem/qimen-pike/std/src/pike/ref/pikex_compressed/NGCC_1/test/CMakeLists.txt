set(PIKEX_COMPRESSED_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)

add_executable(pike-compressed-test_${SVARIANT_LOWER} ${PIKEX_COMPRESSED_DIR}/test/pike-compressed-test.c)
target_include_directories(pike-compressed-test_${SVARIANT_LOWER} PRIVATE
    ${PIKEX_COMPRESSED_DIR}/include
    ${INC_PIKE} ${INC_PIKE_${SVARIANT_UPPER}}
    ${INC_EC} ${INC_GF} ${INC_COMMON}
    ${INC_PRECOMP_${SVARIANT_UPPER}} ${INC_PUBLIC})
target_link_libraries(pike-compressed-test_${SVARIANT_LOWER}
    ${LIB_PIKE_${SVARIANT_UPPER}}_compressed
    ${LIB_ID2ISO_${SVARIANT_UPPER}} ${LIB_HD_${SVARIANT_UPPER}}
    ${LIB_INTBIG} ${GMP} pike_common_sys)

add_executable(pike-compressed-kem-test_${SVARIANT_LOWER} ${PIKEX_COMPRESSED_DIR}/test/pike-compressed-kem-test.c)
target_include_directories(pike-compressed-kem-test_${SVARIANT_LOWER} PRIVATE
    ${PIKEX_COMPRESSED_DIR}/include
    ${INC_PIKE} ${INC_PIKE_${SVARIANT_UPPER}}
    ${INC_EC} ${INC_GF} ${INC_COMMON}
    ${INC_PRECOMP_${SVARIANT_UPPER}} ${INC_PUBLIC})
target_link_libraries(pike-compressed-kem-test_${SVARIANT_LOWER}
    ${LIB_PIKE_${SVARIANT_UPPER}}_compressed
    ${LIB_ID2ISO_${SVARIANT_UPPER}} ${LIB_HD_${SVARIANT_UPPER}}
    ${LIB_INTBIG} ${GMP} pike_common_sys)

if(ENABLE_TESTS)
    add_test(pike-compressed-test_${SVARIANT_LOWER} pike-compressed-test_${SVARIANT_LOWER} 100)
    add_test(pike-compressed-kem-test_${SVARIANT_LOWER} pike-compressed-kem-test_${SVARIANT_LOWER} 100)
endif()
