option(ENABLE_NGCC_PIKE "Build NGCC PIKE adapter KAT targets." ON)

if(NOT ENABLE_NGCC_PIKE)
    return()
endif()

if(NOT ENABLE_COMPRESSED)
    message(FATAL_ERROR "NGCC PIKE KAT adapter now uses pikex_compressed; build with ENABLE_COMPRESSED=ON.")
endif()

set(NGCC_PIKE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(NGCC_PIKE_COMMON_DIR ${NGCC_PIKE_DIR}/common)
set(NGCC_PIKE_KAT_OUTPUT_DIR "${PROJECT_SOURCE_DIR}/../Test_Vector" CACHE PATH "Output directory for NGCC PIKE KAT files.")
file(MAKE_DIRECTORY "${NGCC_PIKE_KAT_OUTPUT_DIR}")

function(add_ngcc_pike_kat_target instance level level_id)
    string(TOLOWER "${instance}" instance_lc)
    string(REPLACE "-" "_" instance_id "${instance_lc}")
    set(target_name "ngcc_pike_kat_${instance_id}")
    if(NOT EXISTS "${NGCC_PIKE_COMMON_DIR}/KAT_KEM.c")
        message(FATAL_ERROR "Missing NGCC PIKE common KAT source: ${NGCC_PIKE_COMMON_DIR}/KAT_KEM.c")
    endif()
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${instance}")

    add_executable(${target_name}
        ${NGCC_PIKE_COMMON_DIR}/KAT_KEM.c
        ${NGCC_PIKE_COMMON_DIR}/KEM_AlgorithmInstance.c
        ${NGCC_PIKE_COMMON_DIR}/drng.c
        ${NGCC_PIKE_COMMON_DIR}/auxfunc.c
    )

    target_include_directories(${target_name} PRIVATE
        ${NGCC_PIKE_COMMON_DIR}
        ${PROJECT_SOURCE_DIR}/src/pike/ref/pikex_compressed/include
        ${PROJECT_SOURCE_DIR}/src/ec/ref/include
        ${PROJECT_SOURCE_DIR}/src/gf/ref/include
        ${PROJECT_SOURCE_DIR}/src/common/generic/include
        ${PROJECT_SOURCE_DIR}/src/precomp/ref/${level}/include
        ${PROJECT_SOURCE_DIR}/include
    )

    target_compile_options(${target_name} PRIVATE ${C_OPT_FLAGS})
    target_compile_definitions(${target_name} PRIVATE
        ALGORITHM_INSTANCE=\"${instance}\"
        NGCC_PIKE_LEVEL=${level_id}
        OUTPUT_BLANK_TEST_VECTORS=0
        NGCC_KAT_DEFAULT_OUTPUT_DIR=\"${NGCC_PIKE_KAT_OUTPUT_DIR}\"
    )
    if("${level}" STREQUAL "NGCC_3")
        target_compile_definitions(${target_name} PRIVATE PIKE_COMPRESSED_SHARED_SECRET_BYTES=64)
    endif()

    target_link_libraries(${target_name} PRIVATE
        pike_pike_${level}_compressed
        pike_id2iso_${level}
        pike_hd_${level}
        pike_intbig_generic
        ${GMP}
        pike_common_sys
        pike_ec_${level}
        pike_precomp_${level}
        pike_gf_${level}
        pike_klpt_${level}
        pike_quaternion_generic
    )

    if(ENABLE_TESTS)
        add_test(NAME ${target_name} COMMAND ${target_name})
        set_tests_properties(${target_name} PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${instance}")
        set_tests_properties(${target_name} PROPERTIES PASS_REGULAR_EXPRESSION "Files have been saved in")
    endif()

endfunction()

add_ngcc_pike_kat_target(NGCC-1 NGCC_1 1)
add_ngcc_pike_kat_target(NGCC-2 NGCC_2 2)
add_ngcc_pike_kat_target(NGCC-3 NGCC_3 3)
