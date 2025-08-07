cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(CURRENT_BUILD_DIR ${CMAKE_BINARY_DIR}/kem/kyber/std)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT} ${CMAKE_PROJECT_ROOT}/include ${CMAKE_PROJECT_ROOT}/utils)

# Find all source code.
file(GLOB KYBER_SOURCES_ORIGIN ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
set(KYBER_SOURCES "")
foreach(SOURCE_PATH ${KYBER_SOURCES_ORIGIN})
    # Only check if the file name contains any keyword, ignore the file path.
    string(REGEX REPLACE ".*\\/" "" SOURCE ${SOURCE_PATH})
    
    # Check if current file related to shake hash.
    if(SOURCE MATCHES "shake")
        # Add it to path only when USE_SHAKE is set.
        if(USE_SHAKE)
            list(APPEND KYBER_SOURCES ${SOURCE_PATH}) 
        endif()
    # Check if current file related to sm3 hash.
    elseif(SOURCE MATCHES "sm3")
        # Add it to path only when USE_SM3 is set.
        if(USE_SM3)
            list(APPEND KYBER_SOURCES ${SOURCE_PATH}) 
        endif()
    else()
        list(APPEND KYBER_SOURCES ${SOURCE_PATH}) 
    endif()

endforeach()

# Compile all mode into objects.
# Then add static lib for each modes.
set(TARGET_OBJECTS_ALL "")
foreach(MODE ${KYBER_MODES})
    # Set as object
    add_library(kyber_objects_${MODE} OBJECT ${KYBER_SOURCES})

    # Set kyber mode.
    target_compile_definitions(kyber_objects_${MODE} PRIVATE KYBER_K=${MODE})
    if(USE_SHAKE)
    target_compile_definitions(kyber_objects_${MODE} PRIVATE USE_SHAKE)
    endif()

    # If we need to compile each algorithm components into shared/static library
    if(COMPILE_COMPONENT_LIBRARY)
    # Add static lib.
    add_library(kyber_static_${MODE} STATIC $<TARGET_OBJECTS:kyber_objects_${MODE}>)
    endif()

    list(APPEND TARGET_OBJECTS_ALL $<TARGET_OBJECTS:kyber_objects_${MODE}>)
    list(APPEND SUPPORT_ALG_OBJECT_TARGET $<TARGET_OBJECTS:kyber_objects_${MODE}>)

endforeach()

# Pass to parents
set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)

# If we need to compile each algorithm components into shared/static library
if(COMPILE_COMPONENT_LIBRARY)
# Set custom target output name
set(SHARED_LIB_NAME "${LIBRARY_PREFIX}pqmagic_kyber_std${DYNAMIC_LIB_SUFFIX}")
set(STATIC_LIB_NAME "${LIBRARY_PREFIX}pqmagic_kyber_std${STATIC_LIB_SUFFIX}")

if(USE_SM3)
    # Add shared lib.
    add_library(
        kyber_target SHARED 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:sm3>
    )

    # Add static lib.
    add_library(
        kyber_static_target STATIC 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:sm3>
    )
elseif(USE_SHAKE)
    # Add shared lib.
    add_library(
        kyber_target SHARED 
        ${TARGET_OBJECTS_ALL}
        $<TARGET_OBJECTS:randombytes>
        $<TARGET_OBJECTS:fips202>
    )

    # Add static lib.
    add_library(
        kyber_static_target STATIC 
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
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # shared：lib*.dll + lib*.lib（import library）
    # static：lib*.lib
    set_target_properties(kyber_target PROPERTIES
        OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_kyber_std"                     # DLL and import
        RUNTIME_OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_kyber_std"             # DLL：*.dll
        ARCHIVE_OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_kyber_std_import"      # import lib：*_import.lib
    )
    set_target_properties(kyber_static_target PROPERTIES
        OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_kyber_std"              # static：*.lib
    )
    else() # gcc
    # shared：lib*.dll + *.dll.a（import library）
    # static：lib*.a
    set_target_properties(kyber_target PROPERTIES
        OUTPUT_NAME "pqmagic_kyber_std"                     # DLL and import
        RUNTIME_OUTPUT_NAME "pqmagic_kyber_std"             # DLL：*.dll
        ARCHIVE_OUTPUT_NAME "pqmagic_kyber_std_import"      # import lib：*_import.dll.a
    )
    set_target_properties(kyber_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_kyber_std"              # static：*.a
    )
    endif()
else()
    # Unix-like（macOS/Linux）
    # shared：lib*.so/lib*.dylib
    # static：lib*.a
    set_target_properties(kyber_target PROPERTIES
        OUTPUT_NAME "pqmagic_kyber_std"
    )
    set_target_properties(kyber_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_kyber_std"
    )
endif()

# Install lib.
install(FILES ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})
install(FILES ${CURRENT_BUILD_DIR}/${STATIC_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})

endif()

# Install api.h params.h to include/kyber dir
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/api.h DESTINATION ${INSTALL_INCLUDE_DIR}/kem/kyber)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/params.h DESTINATION ${INSTALL_INCLUDE_DIR}/kem/kyber)
# install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION ${INSTALL_INCLUDE_DIR}/kyber)
