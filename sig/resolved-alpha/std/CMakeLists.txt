include(${CMAKE_SOURCE_DIR}/cmake/PQMagicReference.cmake)
add_compile_options(${PQMAGIC_REFERENCE_WARNING_OPTIONS})

set(RESOLVED_ALPHA_MODES 160f 160s 256f 256s 384f 384s 512f 512s)
set(RESOLVED_ALPHA_CORE_FILES
    bavc.c enc.c prg.c fields.c instances.c quicksilver.c rsd.c random_oracle.c
    tccr.c universal_hashing.c utils.c voleith_impl.c vole.c auxfunc.c
    SIG_AlgorithmInstance.c
)

foreach(MODE IN LISTS RESOLVED_ALPHA_MODES)
    set(MODE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${MODE})
    set(MODE_SOURCES "")
    foreach(SOURCE_FILE IN LISTS RESOLVED_ALPHA_CORE_FILES)
        list(APPEND MODE_SOURCES ${MODE_DIR}/${SOURCE_FILE})
    endforeach()
    set(TARGET_NAME resolved_alpha_${MODE})
    set(NAMESPACE_PREFIX pqmagic_resolved_alpha_${MODE}_std_)
    pqmagic_add_reference_variant(${TARGET_NAME} ${NAMESPACE_PREFIX}
        NAMESPACE_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h
        OUTPUT_NAME pqmagic_resolved_alpha_${MODE}_std
        SOURCES ${MODE_SOURCES}
        INCLUDE_DIRECTORIES ${MODE_DIR} ${CMAKE_SOURCE_DIR}
        DEFINITIONS XOF_PSEUDO PQMAGIC_USE_SYSTEM_RANDOM
    )

    if(ENABLE_TEST)
        add_executable(test_resolved_alpha_${MODE}
            ${CMAKE_SOURCE_DIR}/sig/reference_test/test_signature.c
            $<TARGET_OBJECTS:${TARGET_NAME}_objects> $<TARGET_OBJECTS:randombytes>)
        target_include_directories(test_resolved_alpha_${MODE} PRIVATE ${MODE_DIR})
        target_compile_definitions(test_resolved_alpha_${MODE} PRIVATE
            XOF_PSEUDO PQMAGIC_USE_SYSTEM_RANDOM PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(test_resolved_alpha_${MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(test_resolved_alpha_${MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
        add_test(NAME resolved_alpha_${MODE}_correctness COMMAND test_resolved_alpha_${MODE})
    endif()

    if(ENABLE_BENCH)
        add_executable(bench_resolved_alpha_${MODE}
            ${CMAKE_SOURCE_DIR}/sig/reference_test/test_speed.c
            $<TARGET_OBJECTS:${TARGET_NAME}_objects> $<TARGET_OBJECTS:randombytes>)
        target_include_directories(bench_resolved_alpha_${MODE} PRIVATE ${MODE_DIR})
        target_compile_definitions(bench_resolved_alpha_${MODE} PRIVATE
            XOF_PSEUDO PQMAGIC_USE_SYSTEM_RANDOM PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(bench_resolved_alpha_${MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(bench_resolved_alpha_${MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()

    if(ENABLE_KAT)
        set(KAT_SOURCES ${MODE_SOURCES})
        list(REMOVE_ITEM KAT_SOURCES ${MODE_DIR}/SIG_AlgorithmInstance.c)
        list(APPEND KAT_SOURCES ${MODE_DIR}/drng.c ${MODE_DIR}/SIG_AlgorithmInstance.c ${MODE_DIR}/KAT_SIG.c)
        add_executable(kat_resolved_alpha_${MODE} ${KAT_SOURCES})
        target_include_directories(kat_resolved_alpha_${MODE} PRIVATE ${MODE_DIR})
        target_compile_definitions(kat_resolved_alpha_${MODE} PRIVATE
            XOF_PSEUDO PQMAGIC_NAMESPACE_PREFIX=pqmagic_kat_resolved_alpha_${MODE}_)
        target_compile_options(kat_resolved_alpha_${MODE} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/namespace.h)
        set_target_properties(kat_resolved_alpha_${MODE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()
endforeach()

set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)
