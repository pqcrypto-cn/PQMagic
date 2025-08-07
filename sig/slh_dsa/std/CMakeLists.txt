cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(CURRENT_BUILD_DIR ${CMAKE_BINARY_DIR}/sig/slh_dsa/std)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT} ${CMAKE_PROJECT_ROOT}/include ${CMAKE_PROJECT_ROOT}/utils)

# Find all source code.
file(GLOB SLH_DSA_SOURCES_ORIGIN ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

set(SLH_DSA_FILTERED_SOURCES "")
set(HARAKA_SOURCES "")
set(HARAKA_THASH_SOURCES "")
set(SHA2_SOURCES "")
set(SHA2_THASH_SOURCES "")
set(SHAKE_SOURCES "")
set(SHAKE_THASH_SOURCES "")
set(SM3_SOURCES "")
set(SM3_THASH_SOURCES "")

# First remove all thash/hash file. 
foreach(SOURCE_PATH ${SLH_DSA_SOURCES_ORIGIN})
    # Only check if the file name contains any keyword, ignore the file path.
    string(REGEX REPLACE ".*\\/" "" SOURCE ${SOURCE_PATH})
    if(SOURCE MATCHES "haraka")
        if(SOURCE MATCHES "thash")
            list(APPEND HARAKA_THASH_SOURCES ${SOURCE_PATH})
        else()
            list(APPEND HARAKA_SOURCES ${SOURCE_PATH})
        endif()
    elseif(SOURCE MATCHES "sha2")
        if(SOURCE MATCHES "thash")
            list(APPEND SHA2_THASH_SOURCES ${SOURCE_PATH})
        else()
            list(APPEND SHA2_SOURCES ${SOURCE_PATH})
        endif()
    elseif(SOURCE MATCHES "shake")
        if(SOURCE MATCHES "thash")
            list(APPEND SHAKE_THASH_SOURCES ${SOURCE_PATH})
        else()
            list(APPEND SHAKE_SOURCES ${SOURCE_PATH})
        endif()
    elseif(SOURCE MATCHES "sm3")
        if(SOURCE MATCHES "thash")
            list(APPEND SM3_THASH_SOURCES ${SOURCE_PATH})
        else()
            list(APPEND SM3_SOURCES ${SOURCE_PATH})
        endif()
    else()
        list(APPEND SLH_DSA_FILTERED_SOURCES ${SOURCE_PATH})
    endif()
endforeach()

# Compile all mode into objects.
# Then add static lib for each modes.
set(TARGET_OBJECTS_ALL "")
foreach(MODE ${SLH_DSA_MODES})

    set(MACRO_MODE ${MODE})
    string(REPLACE "-" "_" MODE "${MODE}")
    string(REPLACE "slh_dsa_" "" MODE "${MODE}")
    string(REGEX MATCH "^[^_]+" HASH_NAME "${MODE}")

    foreach(THASH ${SLH_DSA_THASH})

        # Append thash source 
        set(SELECTED_HASH_SOURCE "")
        set(SLH_DSA_SOURCES ${SLH_DSA_FILTERED_SOURCES})
        if(HASH_NAME MATCHES "haraka")
            list(
                APPEND 
                SELECTED_HASH_SOURCE 
                ${HARAKA_SOURCES} 
            )
            foreach(SOURCE_PATH ${HARAKA_THASH_SOURCES})
                # Only check if the file name contains any keyword, ignore the file path.
                string(REGEX REPLACE ".*\\/" "" SOURCE ${SOURCE_PATH})
                if(SOURCE MATCHES "${THASH}")
                    list(APPEND SELECTED_HASH_SOURCE ${SOURCE_PATH})
                endif()
            endforeach()
        elseif(HASH_NAME MATCHES "sha2")
            list(
                APPEND 
                SELECTED_HASH_SOURCE 
                ${SHA2_SOURCES} 
            )
            foreach(SOURCE_PATH ${SHA2_THASH_SOURCES})
                # Only check if the file name contains any keyword, ignore the file path.
                string(REGEX REPLACE ".*\\/" "" SOURCE ${SOURCE_PATH})
                if(SOURCE MATCHES "${THASH}")
                    list(APPEND SELECTED_HASH_SOURCE ${SOURCE_PATH})
                endif()
            endforeach()
        elseif(HASH_NAME MATCHES "shake")
            list(
                APPEND 
                SELECTED_HASH_SOURCE 
                ${SHAKE_SOURCES} 
            )
            foreach(SOURCE_PATH ${SHAKE_THASH_SOURCES})
                # Only check if the file name contains any keyword, ignore the file path.
                string(REGEX REPLACE ".*\\/" "" SOURCE ${SOURCE_PATH})
                if(SOURCE MATCHES "${THASH}")
                    list(APPEND SELECTED_HASH_SOURCE ${SOURCE_PATH})
                endif()
            endforeach()
        elseif(HASH_NAME MATCHES "sm3")
            list(
                APPEND 
                SELECTED_HASH_SOURCE 
                ${SM3_SOURCES} 
            )
            foreach(SOURCE_PATH ${SM3_THASH_SOURCES})
                # Only check if the file name contains any keyword, ignore the file path.
                string(REGEX REPLACE ".*\\/" "" SOURCE ${SOURCE_PATH})
                if(SOURCE MATCHES "${THASH}")
                    list(APPEND SELECTED_HASH_SOURCE ${SOURCE_PATH})
                endif()
            endforeach()
        else()
            message(FATAL_ERROR "Current not support hash function: ${HASH_NAME}")
        endif()

        list(APPEND SLH_DSA_SOURCES ${SELECTED_HASH_SOURCE})

        # Set as object
        add_library(slh_dsa_objects_${MODE}_${THASH} OBJECT ${SLH_DSA_SOURCES})

        # Set slh_dsa mode.
        target_compile_definitions(
            slh_dsa_objects_${MODE}_${THASH} 
            PRIVATE SLH_DSA_MODE=${MACRO_MODE} 
            THASH=${THASH}
            SLH_DSA_HASH_MODE_NAMESPACE=${MODE}
        )

        # If we need to compile each algorithm components into shared/static library
        if(COMPILE_COMPONENT_LIBRARY)
        # Add static lib.
        add_library(slh_dsa_static_${MODE}_${THASH} STATIC $<TARGET_OBJECTS:slh_dsa_objects_${MODE}_${THASH}>)
        endif()

        list(APPEND TARGET_OBJECTS_ALL $<TARGET_OBJECTS:slh_dsa_objects_${MODE}_${THASH}>)
        list(APPEND SUPPORT_ALG_OBJECT_TARGET $<TARGET_OBJECTS:slh_dsa_objects_${MODE}_${THASH}>)
    
    endforeach()

endforeach()

# Pass to parents
set(SUPPORT_ALG_OBJECT_TARGET ${SUPPORT_ALG_OBJECT_TARGET} PARENT_SCOPE)

# If we need to compile each algorithm components into shared/static library
if(COMPILE_COMPONENT_LIBRARY)
# Set custom target output name
set(SHARED_LIB_NAME "${LIBRARY_PREFIX}pqmagic_slh_dsa_std${DYNAMIC_LIB_SUFFIX}")
set(STATIC_LIB_NAME "${LIBRARY_PREFIX}pqmagic_slh_dsa_std${STATIC_LIB_SUFFIX}")

# Add shared lib.
add_library(
    slh_dsa_target SHARED 
    ${TARGET_OBJECTS_ALL}
    $<TARGET_OBJECTS:randombytes>
    $<TARGET_OBJECTS:sm3>
    $<TARGET_OBJECTS:fips202>
)

# Add static lib.
add_library(
    slh_dsa_static_target STATIC 
    ${TARGET_OBJECTS_ALL}
    $<TARGET_OBJECTS:randombytes>
    $<TARGET_OBJECTS:sm3>
    $<TARGET_OBJECTS:fips202>
)

# Set library name.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Windows has different rules.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # shared：lib*.dll + lib*.lib（import library）
    # static：lib*.lib
    set_target_properties(slh_dsa_target PROPERTIES
        OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_slh_dsa_std"                     # DLL and import
        RUNTIME_OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_slh_dsa_std"             # DLL：*.dll
        ARCHIVE_OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_slh_dsa_std_import"      # import lib：*_import.lib
    )
    set_target_properties(slh_dsa_static_target PROPERTIES
        OUTPUT_NAME "${LIBRARY_PREFIX}pqmagic_slh_dsa_std"              # static：*.lib
    )
    else() # gcc
    # shared：lib*.dll + *.dll.a（import library）
    # static：lib*.a
    set_target_properties(slh_dsa_target PROPERTIES
        OUTPUT_NAME "pqmagic_slh_dsa_std"                     # DLL and import
        RUNTIME_OUTPUT_NAME "pqmagic_slh_dsa_std"             # DLL：*.dll
        ARCHIVE_OUTPUT_NAME "pqmagic_slh_dsa_std_import"      # import lib：*_import.dll.a
    )
    set_target_properties(slh_dsa_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_slh_dsa_std"              # static：*.a
    )
    endif()
else()
    # Unix-like（macOS/Linux）
    # shared：lib*.so/lib*.dylib
    # static：lib*.a
    set_target_properties(slh_dsa_target PROPERTIES
        OUTPUT_NAME "pqmagic_slh_dsa_std"
    )
    set_target_properties(slh_dsa_static_target PROPERTIES
        OUTPUT_NAME "pqmagic_slh_dsa_std"
    )
endif()

# Install lib.
install(FILES ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})
install(FILES ${CURRENT_BUILD_DIR}/${STATIC_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})

endif()

# Install api.h params.h config.h to include/slh_dsa dir
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/api.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/slh_dsa/std)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/params.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/slh_dsa/std)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/slh_dsa/std)
