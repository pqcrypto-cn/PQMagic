find_path(QIMEN_GMP_INCLUDE_DIR gmp.h REQUIRED)
find_library(QIMEN_GMP_LIBRARY gmp REQUIRED)
add_compile_options(${PQMAGIC_REFERENCE_WARNING_OPTIONS})
if(NOT MSVC)
    add_compile_options(-Wno-extra-semi -Wno-missing-field-initializers)
endif()

set(QIMEN_COMMON_SOURCES
    src/common/generic/aes_c.c
    src/common/generic/fips202.c
    src/common/generic/pike_hash.c
    src/common/generic/randombytes_system.c
    src/common/generic/tools.c
    src/ec/ref/ecx/biextension.c
    src/ec/ref/ecx/isog_chains.c
    src/ec/ref/ecx/kps.c
    src/ec/ref/ecx/xeval.c
    src/ec/ref/ecx/xisog.c
    src/ec/ref/pike_ecx/basis.c
    src/ec/ref/pike_ecx/ec.c
    src/gf/ref/gfx/fp2.c
    src/gf/ref/gfx/mp.c
    src/hd/ref/hdx/hd.c
    src/hd/ref/hdx/theta_isogenies.c
    src/hd/ref/hdx/theta_structure.c
    src/id2iso/ref/id2isox/id2iso.c
    src/intbig/ref/generic/intbig.c
    src/klpt/ref/klptx/tools.c
    src/ngcc/common/KEM_AlgorithmInstance.c
    src/pike/ref/pikex_compressed/pike_compressed.c
    src/quaternion/ref/generic/algebra.c
    src/quaternion/ref/generic/dim2.c
    src/quaternion/ref/generic/dim4.c
    src/quaternion/ref/generic/finit.c
    src/quaternion/ref/generic/ideal.c
    src/quaternion/ref/generic/integers.c
    src/quaternion/ref/generic/lattice.c
    src/quaternion/ref/generic/lll.c
    src/quaternion/ref/generic/matkermod.c
    src/quaternion/ref/generic/printer.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(QIMEN_ARCH_DEFINITIONS RADIX_64 TARGET_ARM64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
    set(QIMEN_ARCH_DEFINITIONS RADIX_32 TARGET_ARM)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    set(QIMEN_ARCH_DEFINITIONS RADIX_64 TARGET_AMD64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686|x86")
    set(QIMEN_ARCH_DEFINITIONS RADIX_32 TARGET_X86)
else()
    set(QIMEN_ARCH_DEFINITIONS RADIX_64 TARGET_OTHER)
endif()
if(UNIX)
    list(APPEND QIMEN_ARCH_DEFINITIONS TARGET_OS_UNIX)
else()
    list(APPEND QIMEN_ARCH_DEFINITIONS TARGET_OS_OTHER)
endif()

# The reference package builds each parameter set as a separate program and
# reuses global symbol names. PQMagic links all levels into one library, so each
# level needs its own namespace.
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/namespace_symbols.txt QIMEN_NAMESPACE_SYMBOLS)
set(QIMEN_NAMESPACE_HEADER ${CMAKE_CURRENT_BINARY_DIR}/namespace.h)
file(WRITE ${QIMEN_NAMESPACE_HEADER}
    "#ifndef PQMAGIC_QIMEN_PIKE_NAMESPACE_H\n#define PQMAGIC_QIMEN_PIKE_NAMESPACE_H\n"
    "#define PQMAGIC_QIMEN_CONCAT_INNER(prefix, symbol) prefix##symbol\n"
    "#define PQMAGIC_QIMEN_CONCAT(prefix, symbol) PQMAGIC_QIMEN_CONCAT_INNER(prefix, symbol)\n"
    "#define PQMAGIC_QIMEN_NAMESPACE(symbol) PQMAGIC_QIMEN_CONCAT(PQMAGIC_NAMESPACE_PREFIX, symbol)\n")
foreach(SYMBOL IN LISTS QIMEN_NAMESPACE_SYMBOLS)
    file(APPEND ${QIMEN_NAMESPACE_HEADER}
        "#define ${SYMBOL} PQMAGIC_QIMEN_NAMESPACE(${SYMBOL})\n")
endforeach()
file(APPEND ${QIMEN_NAMESPACE_HEADER} "#endif\n")

function(pqmagic_add_qimen_pike_variant LEVEL FP_SOURCE)
    set(TARGET_NAME qimen_pike_ngcc_${LEVEL})
    set(NAMESPACE_PREFIX pqmagic_qimen_pike_ngcc_${LEVEL}_std_)
    set(LEVEL_NAME NGCC_${LEVEL})
    set(LEVEL_SOURCES
        ${QIMEN_COMMON_SOURCES}
        src/gf/ref/${LEVEL_NAME}/${FP_SOURCE}
        src/precomp/ref/${LEVEL_NAME}/endomorphism_action.c
        src/precomp/ref/${LEVEL_NAME}/gf_constants.c
        src/precomp/ref/${LEVEL_NAME}/klpt_constants.c
        src/precomp/ref/${LEVEL_NAME}/quaternion_data.c
        src/precomp/ref/${LEVEL_NAME}/torsion_constants.c
    )
    set(INCLUDE_DIRECTORIES
        ${QIMEN_GMP_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common/generic/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ec/ref/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ec/ref/${LEVEL_NAME}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/gf/ref/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/gf/ref/${LEVEL_NAME}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hd/ref/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/id2iso/ref/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/intbig/ref/generic/common
        ${CMAKE_CURRENT_SOURCE_DIR}/src/intbig/ref/generic/gmp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/intbig/ref/generic/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/klpt/ref/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ngcc/common
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pike/ref/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pike/ref/${LEVEL_NAME}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pike/ref/pikex_compressed/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/precomp/ref/${LEVEL_NAME}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/quaternion/ref/generic/common
        ${CMAKE_CURRENT_SOURCE_DIR}/src/quaternion/ref/generic/include
    )
    set(DEFINITIONS
        ${QIMEN_ARCH_DEFINITIONS}
        PIKE_XOF_BACKEND=2
        NGCC_PIKE_LEVEL=${LEVEL}
        ALGORITHM_INSTANCE="NGCC-${LEVEL}"
    )
    if(LEVEL EQUAL 3)
        list(APPEND DEFINITIONS PIKE_COMPRESSED_SHARED_SECRET_BYTES=64)
    endif()

    pqmagic_add_reference_variant(${TARGET_NAME} ${NAMESPACE_PREFIX}
        NAMESPACE_HEADER ${QIMEN_NAMESPACE_HEADER}
        OUTPUT_NAME pqmagic_qimen_pike_ngcc_${LEVEL}_std
        SOURCES ${LEVEL_SOURCES}
        INCLUDE_DIRECTORIES ${INCLUDE_DIRECTORIES}
        DEFINITIONS ${DEFINITIONS}
    )

    if(ENABLE_TEST)
        add_executable(test_qimen_pike_ngcc_${LEVEL}
            test/test_qimen_pike.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(test_qimen_pike_ngcc_${LEVEL} PRIVATE ${INCLUDE_DIRECTORIES})
        target_compile_definitions(test_qimen_pike_ngcc_${LEVEL} PRIVATE
            ${DEFINITIONS} PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(test_qimen_pike_ngcc_${LEVEL} PRIVATE -include ${QIMEN_NAMESPACE_HEADER})
        target_link_libraries(test_qimen_pike_ngcc_${LEVEL} PRIVATE ${QIMEN_GMP_LIBRARY})
        set_target_properties(test_qimen_pike_ngcc_${LEVEL} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
        add_test(NAME qimen_pike_ngcc_${LEVEL}_correctness COMMAND test_qimen_pike_ngcc_${LEVEL})
    endif()

    if(ENABLE_BENCH)
        add_executable(bench_qimen_pike_ngcc_${LEVEL}
            test/bench_qimen_pike.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(bench_qimen_pike_ngcc_${LEVEL} PRIVATE ${INCLUDE_DIRECTORIES})
        target_compile_definitions(bench_qimen_pike_ngcc_${LEVEL} PRIVATE
            ${DEFINITIONS} PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX})
        target_compile_options(bench_qimen_pike_ngcc_${LEVEL} PRIVATE -include ${QIMEN_NAMESPACE_HEADER})
        target_link_libraries(bench_qimen_pike_ngcc_${LEVEL} PRIVATE ${QIMEN_GMP_LIBRARY})
        set_target_properties(bench_qimen_pike_ngcc_${LEVEL} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()

    if(ENABLE_KAT)
        add_executable(kat_qimen_pike_ngcc_${LEVEL}
            test/test_qimen_pike_kat.c $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        target_include_directories(kat_qimen_pike_ngcc_${LEVEL} PRIVATE ${INCLUDE_DIRECTORIES})
        target_compile_definitions(kat_qimen_pike_ngcc_${LEVEL} PRIVATE
            ${DEFINITIONS}
            PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX}
            QIMEN_KAT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/test-vectors/KAT_KEM_NGCC-${LEVEL}.txt")
        target_compile_options(kat_qimen_pike_ngcc_${LEVEL} PRIVATE -include ${QIMEN_NAMESPACE_HEADER})
        target_link_libraries(kat_qimen_pike_ngcc_${LEVEL} PRIVATE ${QIMEN_GMP_LIBRARY})
        set_target_properties(kat_qimen_pike_ngcc_${LEVEL} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
        add_test(NAME qimen_pike_ngcc_${LEVEL}_kat COMMAND kat_qimen_pike_ngcc_${LEVEL})
    endif()

    set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)
endfunction()

pqmagic_add_qimen_pike_variant(1 fp_p479.c)
pqmagic_add_qimen_pike_variant(2 fp_p765.c)
pqmagic_add_qimen_pike_variant(3 fp_p1534.c)

set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)
list(APPEND PQMAGIC_EXTERNAL_LIBRARIES ${QIMEN_GMP_LIBRARY})
set(PQMAGIC_EXTERNAL_LIBRARIES ${PQMAGIC_EXTERNAL_LIBRARIES} PARENT_SCOPE)
