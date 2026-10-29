include(${CMAKE_SOURCE_DIR}/cmake/PQMagicReference.cmake)
add_compile_options(${PQMAGIC_REFERENCE_WARNING_OPTIONS})

set(AIGIS_ENC_PLUS_SOURCES
    cbd.c fips202.c poly.c reduce.c precomp.c ntt.c polyvec.c owcpa.c kem.c
    verify.c hashkdf.c gen_a.c pack.c randombytes.c
)
set(AIGIS_ENC_PLUS_SOURCE_PATHS "")
foreach(SOURCE_FILE IN LISTS AIGIS_ENC_PLUS_SOURCES)
    list(APPEND AIGIS_ENC_PLUS_SOURCE_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE})
endforeach()

foreach(MODE 1 2 3)
    set(TARGET_NAME aigis_enc_plus_${MODE})
    set(NAMESPACE_PREFIX pqmagic_aigis_enc_plus_${MODE}_std_)
    pqmagic_add_reference_variant(${TARGET_NAME} ${NAMESPACE_PREFIX}
        NAMESPACE_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h
        OUTPUT_NAME pqmagic_aigis_enc_plus_${MODE}_std
        SOURCES ${AIGIS_ENC_PLUS_SOURCE_PATHS}
        INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}
        DEFINITIONS PARAMS=${MODE} USE_SHA3
    )

    if(ENABLE_TEST)
        add_executable(test_aigis_enc_plus_${MODE}
            test/test_aigis_enc_plus.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(test_aigis_enc_plus_${MODE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(test_aigis_enc_plus_${MODE} PRIVATE PARAMS=${MODE} USE_SHA3
            PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(test_aigis_enc_plus_${MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(test_aigis_enc_plus_${MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
        add_test(NAME aigis_enc_plus_${MODE}_correctness COMMAND test_aigis_enc_plus_${MODE})
    endif()

    if(ENABLE_BENCH)
        add_executable(bench_aigis_enc_plus_${MODE}
            test/test_speed.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(bench_aigis_enc_plus_${MODE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(bench_aigis_enc_plus_${MODE} PRIVATE PARAMS=${MODE} USE_SHA3
            PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(bench_aigis_enc_plus_${MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(bench_aigis_enc_plus_${MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()

    if(ENABLE_KAT)
        set(KAT_TARGET kat_aigis_enc_plus_${MODE})
        add_executable(${KAT_TARGET}
            cbd.c fips202.c poly.c reduce.c precomp.c ntt.c polyvec.c owcpa.c kem.c
            verify.c hashkdf.c gen_a.c pack.c
            kat_test/auxfunc.c kat_test/drng.c kat_test/rng.c
            kat_test/KEM_AlgorithmInstance.c kat_test/KAT_KEM.c)
        target_include_directories(${KAT_TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/kat_test)
        target_compile_definitions(${KAT_TARGET} PRIVATE PARAMS=${MODE} USE_NICCS_API
            PQMAGIC_NAMESPACE_PREFIX=pqmagic_kat_aigis_enc_plus_${MODE}_)
        target_compile_options(${KAT_TARGET} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h
            -Wno-incompatible-pointer-types-discards-qualifiers -Wno-pointer-sign)
        set_target_properties(${KAT_TARGET} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()
endforeach()

set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)
