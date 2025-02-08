cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(CURRENT_BUILD_DIR ${CMAKE_BINARY_DIR}/sig/aigis-sig/std)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT} ${CMAKE_PROJECT_ROOT}/include ${CMAKE_PROJECT_ROOT}/utils)

# Find all source code.
file(GLOB AIGIS_SIG_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

# Compile all mode into objects.
# Then add static lib for each modes.
set(TARGET_OBJECTS_ALL "")
foreach(MODE ${AIGIS_SIG_MODES})
    # Set as object
    add_library(aigis_sig_objects_${MODE} OBJECT ${AIGIS_SIG_SOURCES})

    # Set aigis_sig mode.
    target_compile_definitions(aigis_sig_objects_${MODE} PRIVATE AIGIS_SIG_MODE=${MODE})
    if(USE_SHAKE)
    target_compile_definitions(aigis_sig_objects_${MODE} PRIVATE USE_SHAKE)
    endif()


    # Add static lib.
    add_library(aigis_sig_static_${MODE} STATIC $<TARGET_OBJECTS:aigis_sig_objects_${MODE}>)

    list(APPEND TARGET_OBJECTS_ALL $<TARGET_OBJECTS:aigis_sig_objects_${MODE}>)
    list(APPEND SUPPORT_ALG_OBJECT_TARGET $<TARGET_OBJECTS:aigis_sig_objects_${MODE}>)

endforeach()

# Pass to parents
set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)

# Set custom target output name
set(SHARED_LIB_NAME "${LIBRARY_PREFIX}pqmagic_aigis_sig_std${DYNAMIC_LIB_SUFFIX}")
set(STATIC_LIB_NAME "${LIBRARY_PREFIX}pqmagic_aigis_sig_std${STATIC_LIB_SUFFIX}")

if(USE_SM3)
    # Add shared lib.
    add_library(
        aigis_sig_target SHARED 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:sm3>
    )

    # Add static lib.
    add_library(
        aigis_sig_static_target STATIC 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:sm3>
    )
elseif(USE_SHAKE)
    # Add shared lib.
    add_library(
        aigis_sig_target SHARED 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:fips202>
    )

    # Add static lib.
    add_library(
        aigis_sig_static_target STATIC 
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
    set_target_properties(aigis_sig_target PROPERTIES
        OUTPUT_NAME "pqmagic_aigis_sig_std"                     # DLL and import
        RUNTIME_OUTPUT_NAME "pqmagic_aigis_sig_std"             # DLL：*.dll
        ARCHIVE_OUTPUT_NAME "pqmagic_aigis_sig_std_import"      # import lib：*_import.lib
    )
    set_target_properties(aigis_sig_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_aigis_sig_std"              # static：*.lib
    )
else()
    # Unix-like（macOS/Linux）
    # shared：lib*.so/lib*.dylib
    # static：lib*.a
    set_target_properties(aigis_sig_target PROPERTIES
        OUTPUT_NAME "pqmagic_aigis_sig_std"
    )
    set_target_properties(aigis_sig_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_aigis_sig_std"
    )
endif()

# Install lib.
install(FILES ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})
install(FILES ${CURRENT_BUILD_DIR}/${STATIC_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})

# Install api.h params.h config.h to include/aigis_sig dir
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/api.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/aigis-sig)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/params.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/aigis-sig)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/aigis-sig)
