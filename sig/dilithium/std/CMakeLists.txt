cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(CURRENT_BUILD_DIR ${CMAKE_BINARY_DIR}/sig/dilithium/std)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT} ${CMAKE_PROJECT_ROOT}/include ${CMAKE_PROJECT_ROOT}/utils)

# Find all source code.
file(GLOB DILITHIUM_SOURCES_ORIGIN ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

set(DILITHIUM_SOURCES "")
# message(${DILITHIUM_SOURCES_ORIGIN})
foreach(SOURCE_PATH ${DILITHIUM_SOURCES_ORIGIN})
    # Only check if the file name contains any keyword, ignore the file path.
    string(REGEX REPLACE ".*\\/" "" SOURCE ${SOURCE_PATH})
    
    # Check if current file related to shake hash.
    if(SOURCE MATCHES "shake")
        # Add it to path only when USE_SHAKE is set.
        if(USE_SHAKE)
            list(APPEND DILITHIUM_SOURCES ${SOURCE_PATH}) 
        endif()
    else()
        list(APPEND DILITHIUM_SOURCES ${SOURCE_PATH}) 
    endif()

endforeach()

# Compile all mode into objects.
# Then add static lib for each modes.
set(TARGET_OBJECTS_ALL "")
foreach(MODE ${DILITHIUM_MODES})
    # Set as object
    add_library(dilithium_objects_${MODE} OBJECT ${DILITHIUM_SOURCES})

    # Set dilithium mode.
    target_compile_definitions(dilithium_objects_${MODE} PRIVATE DILITHIUM_MODE=${MODE})
    if(USE_SHAKE)
    target_compile_definitions(dilithium_objects_${MODE} PRIVATE USE_SHAKE)
    endif()

    # Add static lib.
    add_library(dilithium_static_${MODE} STATIC $<TARGET_OBJECTS:dilithium_objects_${MODE}>)

    list(APPEND TARGET_OBJECTS_ALL $<TARGET_OBJECTS:dilithium_objects_${MODE}>)
    list(APPEND SUPPORT_ALG_OBJECT_TARGET $<TARGET_OBJECTS:dilithium_objects_${MODE}>)

endforeach()

# Pass to parents
set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)

# Set custom target output name
set(SHARED_LIB_NAME "${LIBRARY_PREFIX}pqmagic_dilithium_std${DYNAMIC_LIB_SUFFIX}")
set(STATIC_LIB_NAME "${LIBRARY_PREFIX}pqmagic_dilithium_std${STATIC_LIB_SUFFIX}")

if(USE_SM3)
    # Add shared lib.
    add_library(
        dilithium_target SHARED 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:sm3>
    )

    # Add static lib.
    add_library(
        dilithium_static_target STATIC 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:sm3>
    )
elseif(USE_SHAKE)
    # Add shared lib.
    add_library(
        dilithium_target SHARED 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:fips202>
    )

    # Add static lib.
    add_library(
        dilithium_static_target STATIC 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:fips202>
    )
else()
    message(FATAL_ERROR "Choose hash mode by -DUSE_SM3=ON or -DUSE_SHAKE=ON")
endif()

# Set library name.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Windows has different rules.
    # shared：*.dll + *.lib（import library）
    # static：*.lib
    set_target_properties(dilithium_target PROPERTIES
        OUTPUT_NAME "pqmagic_dilithium_std"                     # DLL and import
        RUNTIME_OUTPUT_NAME "pqmagic_dilithium_std"             # DLL：*.dll
        ARCHIVE_OUTPUT_NAME "pqmagic_dilithium_std_import"      # import lib：*_import.lib
    )
    set_target_properties(dilithium_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_dilithium_std"              # static：*.lib
    )
else()
    # Unix-like（macOS/Linux）
    # shared：lib*.so/lib*.dylib
    # static：lib*.a
    set_target_properties(dilithium_target PROPERTIES
        OUTPUT_NAME "pqmagic_dilithium_std"
    )
    set_target_properties(dilithium_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_dilithium_std"
    )
endif()

# Install lib.
install(FILES ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})
install(FILES ${CURRENT_BUILD_DIR}/${STATIC_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})

# Install api.h params.h config.h to include/dilithium dir
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/api.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/dilithium)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/params.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/dilithium)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/dilithium)