# set(SOURCE_FILES_HD_GENERIC_REF_TESTS
#     ${HDX_DIR}/test/hd_test.c
# )
# add_executable(sqisign_test_hd_${SVARIANT_LOWER} ${SOURCE_FILES_HD_GENERIC_REF_TESTS})
# target_link_libraries(sqisign_test_hd_${SVARIANT_LOWER} ${LIB_HD_${SVARIANT_UPPER}} ${LIB_ID2ISO_${SVARIANT_UPPER}} ${LIB_KLPT_${SVARIANT_UPPER}} ${LIB_QUATERNION} ${LIB_PRECOMP_${SVARIANT_UPPER}} ${LIB_EC_${SVARIANT_UPPER}} ${LIB_GF_${SVARIANT_UPPER}} ${LIB_INTBIG} ${LIB_PUBLIC} ${GMP} sqisign_common_sys )
# target_include_directories(sqisign_test_hd_${SVARIANT_LOWER} PRIVATE ${INC_PUBLIC} ${INC_INTBIG} ${INC_EC} ${INC_PRECOMP_${SVARIANT_UPPER}} ${INC_QUATERNION} ${INC_KLPT} ${INC_ID2ISO} ${INC_HD} ${INC_GF} ${INC_GF_${SVARIANT_UPPER}} ${INC_COMMON} ./include/ )

# add_test(sqisign_test_hd_${SVARIANT_LOWER} sqisign_test_hd_${SVARIANT_LOWER})
