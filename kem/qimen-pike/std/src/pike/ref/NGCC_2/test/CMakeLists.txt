add_executable(pike-test_${SVARIANT_LOWER} ${PIKEX_DIR}/test/pike-test.c)
target_include_directories(pike-test_${SVARIANT_LOWER} PRIVATE ${INC_PIKE} ${INC_PIKE_${SVARIANT_UPPER}} ${INC_EC} ${INC_GF} ${INC_COMMON} ${INC_PRECOMP_${SVARIANT_UPPER}} ${INC_PUBLIC})
target_link_libraries(pike-test_${SVARIANT_LOWER} ${LIB_PIKE_${SVARIANT_UPPER}} ${LIB_ID2ISO_${SVARIANT_UPPER}} ${LIB_HD_${SVARIANT_UPPER}} ${LIB_INTBIG} ${GMP} pike_common_sys)

add_executable(pike-kem-test_${SVARIANT_LOWER} ${PIKEX_DIR}/test/pike-kem-test.c)
target_include_directories(pike-kem-test_${SVARIANT_LOWER} PRIVATE ${INC_PIKE} ${INC_PIKE_${SVARIANT_UPPER}} ${INC_EC} ${INC_GF} ${INC_COMMON} ${INC_PRECOMP_${SVARIANT_UPPER}} ${INC_PUBLIC})
target_link_libraries(pike-kem-test_${SVARIANT_LOWER} ${LIB_PIKE_${SVARIANT_UPPER}} ${LIB_ID2ISO_${SVARIANT_UPPER}} ${LIB_HD_${SVARIANT_UPPER}} ${LIB_INTBIG} ${GMP} pike_common_sys)

add_test(pike-test_${SVARIANT_LOWER} pike-test_${SVARIANT_LOWER} 100)
add_test(pike-kem-test_${SVARIANT_LOWER} pike-kem-test_${SVARIANT_LOWER} 100)
