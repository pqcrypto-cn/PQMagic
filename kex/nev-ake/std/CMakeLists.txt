include(${CMAKE_SOURCE_DIR}/cmake/PQMagicReference.cmake)
add_compile_options(${PQMAGIC_REFERENCE_WARNING_OPTIONS})

set(NEV_AKE_SOURCES
    poly.c ntt.c owpke.c owkem.c verify.c sample.c pack.c cca.c cpa.c ake.c
    symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c randombytes.c
)
set(NEV_AKE_SOURCE_PATHS "")
foreach(SOURCE_FILE IN LISTS NEV_AKE_SOURCES)
    list(APPEND NEV_AKE_SOURCE_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE})
endforeach()

set(NEV_AKE_MODES
    512_769_c 1024_769_c 2048_769_c
    512_1409 1024_1409 2048_1409
    512_769 1024_769 2048_769
)

set(NEV_AKE_PARAM 1)
foreach(NEV_AKE_MODE IN LISTS NEV_AKE_MODES)
    set(TARGET_NAME nev_ake_${NEV_AKE_MODE})
    set(NAMESPACE_PREFIX pqmagic_nev_ake_${NEV_AKE_MODE}_std_)
    pqmagic_add_reference_variant(${TARGET_NAME} ${NAMESPACE_PREFIX}
        NAMESPACE_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h
        OUTPUT_NAME pqmagic_nev_ake_${NEV_AKE_MODE}_std
        SOURCES ${NEV_AKE_SOURCE_PATHS}
        INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/symmetrics
        DEFINITIONS PARAMS=${NEV_AKE_PARAM} USE_SHA3
    )

    if(ENABLE_TEST)
        add_executable(test_nev_ake_${NEV_AKE_MODE}
            test/test_nev_ake.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(test_nev_ake_${NEV_AKE_MODE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(test_nev_ake_${NEV_AKE_MODE} PRIVATE PARAMS=${NEV_AKE_PARAM} USE_SHA3
            PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(test_nev_ake_${NEV_AKE_MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(test_nev_ake_${NEV_AKE_MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
        add_test(NAME nev_ake_${NEV_AKE_MODE}_correctness COMMAND test_nev_ake_${NEV_AKE_MODE})
    endif()

    if(ENABLE_BENCH)
        add_executable(bench_nev_ake_${NEV_AKE_MODE}
            test/test_speed.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(bench_nev_ake_${NEV_AKE_MODE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(bench_nev_ake_${NEV_AKE_MODE} PRIVATE PARAMS=${NEV_AKE_PARAM} USE_SHA3
            PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(bench_nev_ake_${NEV_AKE_MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(bench_nev_ake_${NEV_AKE_MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()

    if(ENABLE_KAT)
        set(KAT_TARGET kat_nev_ake_${NEV_AKE_MODE})
        add_executable(${KAT_TARGET}
            poly.c ntt.c owpke.c owkem.c verify.c sample.c pack.c cca.c cpa.c ake.c
            symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c
            kat_test/rng.c kat_test/drng.c kat_test/KEX_AlgorithmInstance.c kat_test/KAT_KEX.c)
        target_include_directories(${KAT_TARGET} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/symmetrics ${CMAKE_CURRENT_SOURCE_DIR}/kat_test)
        target_compile_definitions(${KAT_TARGET} PRIVATE PARAMS=${NEV_AKE_PARAM} USE_ICCS
            PQMAGIC_NAMESPACE_PREFIX=pqmagic_kat_nev_ake_${NEV_AKE_MODE}_)
        target_compile_options(${KAT_TARGET} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h
            -Wno-incompatible-pointer-types-discards-qualifiers -Wno-pointer-sign)
        set_target_properties(${KAT_TARGET} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()
    math(EXPR NEV_AKE_PARAM "${NEV_AKE_PARAM} + 1")
endforeach()

set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)
