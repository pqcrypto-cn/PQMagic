include(CMakeParseArguments)

function(pqmagic_add_reference_variant TARGET_NAME NAMESPACE_PREFIX)
    set(options)
    set(oneValueArgs NAMESPACE_HEADER OUTPUT_NAME)
    set(multiValueArgs SOURCES INCLUDE_DIRECTORIES DEFINITIONS)
    cmake_parse_arguments(REF "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_library(${TARGET_NAME}_objects OBJECT ${REF_SOURCES})
    target_include_directories(${TARGET_NAME}_objects PRIVATE ${REF_INCLUDE_DIRECTORIES})
    target_compile_definitions(${TARGET_NAME}_objects PRIVATE
        ${REF_DEFINITIONS}
        PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX}
    )

    if(MSVC)
        target_compile_options(${TARGET_NAME}_objects PRIVATE "/FI${REF_NAMESPACE_HEADER}")
    else()
        target_compile_options(${TARGET_NAME}_objects PRIVATE
            -include ${REF_NAMESPACE_HEADER}
            -Wno-incompatible-pointer-types-discards-qualifiers
            -Wno-pointer-sign
        )
    endif()

    list(APPEND SUPPORT_ALG_OBJECT_TARGET $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
    set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)

    if(COMPILE_COMPONENT_LIBRARY)
        add_library(${TARGET_NAME}_static STATIC $<TARGET_OBJECTS:${TARGET_NAME}_objects>)
        set_target_properties(${TARGET_NAME}_static PROPERTIES OUTPUT_NAME ${REF_OUTPUT_NAME})
    endif()
endfunction()

function(pqmagic_add_reference_executable TARGET_NAME NAMESPACE_PREFIX)
    set(options)
    set(oneValueArgs NAMESPACE_HEADER)
    set(multiValueArgs SOURCES INCLUDE_DIRECTORIES DEFINITIONS LIBRARIES)
    cmake_parse_arguments(REF "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_executable(${TARGET_NAME} ${REF_SOURCES})
    target_include_directories(${TARGET_NAME} PRIVATE ${REF_INCLUDE_DIRECTORIES})
    target_compile_definitions(${TARGET_NAME} PRIVATE
        ${REF_DEFINITIONS}
        PQMAGIC_NAMESPACE_PREFIX=${NAMESPACE_PREFIX}
    )
    target_link_libraries(${TARGET_NAME} PRIVATE ${REF_LIBRARIES})
    set_target_properties(${TARGET_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )

    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE "/FI${REF_NAMESPACE_HEADER}")
    else()
        target_compile_options(${TARGET_NAME} PRIVATE
            -include ${REF_NAMESPACE_HEADER}
            -Wno-incompatible-pointer-types-discards-qualifiers
            -Wno-pointer-sign
        )
    endif()
endfunction()
