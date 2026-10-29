include(${CMAKE_SOURCE_DIR}/cmake/PQMagicReference.cmake)
add_compile_options(${PQMAGIC_REFERENCE_WARNING_OPTIONS})

set(NEV_SOURCES
    poly.c ntt.c owpke.c verify.c sample.c pack.c cca.c cpa.c
    symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c randombytes.c
)
set(NEV_SOURCE_PATHS "")
foreach(SOURCE_FILE IN LISTS NEV_SOURCES)
    list(APPEND NEV_SOURCE_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE})
endforeach()

set(NEV_MODES
    512_769_c 1024_769_c 2048_769_c
    512_1409 1024_1409 2048_1409
    512_3329 1024_3329 2048_3329
    512_769 1024_769 2048_769
)

set(NEV_PARAM 1)
foreach(NEV_MODE IN LISTS NEV_MODES)
    set(TARGET_NAME nev_${NEV_MODE})
    set(NAMESPACE_PREFIX pqmagic_nev_${NEV_MODE}_std_)
    pqmagic_add_reference_variant(${TARGET_NAME} ${NAMESPACE_PREFIX}
        NAMESPACE_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h
        OUTPUT_NAME pqmagic_nev_${NEV_MODE}_std
        SOURCES ${NEV_SOURCE_PATHS}
        INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/symmetrics
        DEFINITIONS PARAMS=${NEV_PARAM} USE_SHA3
    )

    if(ENABLE_TEST)
        add_executable(test_nev_${NEV_MODE}
            test/test_nev.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(test_nev_${NEV_MODE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(test_nev_${NEV_MODE} PRIVATE
            PARAMS=${NEV_PARAM} USE_SHA3 PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(test_nev_${NEV_MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(test_nev_${NEV_MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
        add_test(NAME nev_${NEV_MODE}_correctness COMMAND test_nev_${NEV_MODE})
    endif()

    if(ENABLE_BENCH)
        add_executable(bench_nev_${NEV_MODE}
            test/test_speed.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(bench_nev_${NEV_MODE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(bench_nev_${NEV_MODE} PRIVATE
            PARAMS=${NEV_PARAM} USE_SHA3 PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(bench_nev_${NEV_MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(bench_nev_${NEV_MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()

    if(ENABLE_KAT)
        set(KAT_TARGET kat_nev_${NEV_MODE})
        add_executable(${KAT_TARGET}
            poly.c ntt.c owpke.c verify.c sample.c pack.c cca.c cpa.c
            symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c
            kat_test/rng.c kat_test/drng.c kat_test/KEM_AlgorithmInstance.c kat_test/KAT_KEM.c)
        target_include_directories(${KAT_TARGET} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/symmetrics ${CMAKE_CURRENT_SOURCE_DIR}/kat_test)
        target_compile_definitions(${KAT_TARGET} PRIVATE PARAMS=${NEV_PARAM} USE_ICCS
            PQMAGIC_NAMESPACE_PREFIX=pqmagic_kat_nev_${NEV_MODE}_)
        target_compile_options(${KAT_TARGET} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h
            -Wno-incompatible-pointer-types-discards-qualifiers -Wno-pointer-sign)
        set_target_properties(${KAT_TARGET} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()
    math(EXPR NEV_PARAM "${NEV_PARAM} + 1")
endforeach()

set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)
