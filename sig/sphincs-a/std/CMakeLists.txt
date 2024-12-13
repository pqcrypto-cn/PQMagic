cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(CURRENT_BUILD_DIR ${CMAKE_BINARY_DIR}/sig/sphincs-a/std)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT} ${CMAKE_PROJECT_ROOT}/include ${CMAKE_PROJECT_ROOT}/utils)

# Find all source code.
file(GLOB SPHINCS_A_SOURCES_ORIGIN ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

set(SPHINCS_A_FILTERED_SOURCES "")
set(HARAKA_SOURCES "")
set(HARAKA_THASH_SOURCES "")
set(SHA2_SOURCES "")
set(SHA2_THASH_SOURCES "")
set(SHAKE_SOURCES "")
set(SHAKE_THASH_SOURCES "")
set(SM3_SOURCES "")
set(SM3_THASH_SOURCES "")

# First remove all thash/hash file. 
foreach(SOURCE_PATH ${SPHINCS_A_SOURCES_ORIGIN})
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
        list(APPEND SPHINCS_A_FILTERED_SOURCES ${SOURCE_PATH})
    endif()
endforeach()

# Compile all mode into static library.
set(TARGET_STATIC_LIBS "")
set(TARGET_STATIC_LIBS_PATH "")
foreach(MODE ${SPHINCS_A_MODES})

    set(MACRO_MODE ${MODE})
    string(REPLACE "-" "_" MODE "${MODE}")
    string(REPLACE "sphincs_a_" "" MODE "${MODE}")
    string(REGEX MATCH "^[^_]+" HASH_NAME "${MODE}")

    foreach(THASH ${SPHINCS_A_THASH})

        # Append thash source 
        set(SELECTED_HASH_SOURCE "")
        set(SPHINCS_A_SOURCES ${SPHINCS_A_FILTERED_SOURCES})
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

        list(APPEND SPHINCS_A_SOURCES ${SELECTED_HASH_SOURCE})

        # Add static lib.
        add_library(sphincs_a_static_${MODE}_${THASH} STATIC ${SPHINCS_A_SOURCES})

        # Set sphincs_a mode.
        target_compile_definitions(
            sphincs_a_static_${MODE}_${THASH} 
            PRIVATE SPHINCS_A_MODE=${MACRO_MODE} 
            THASH=${THASH}
            SPHINCS_A_HASH_MODE_NAMESPACE=${MODE}
        )
        
        # Recored all modes target except for last one.
        list(APPEND TARGET_STATIC_LIBS sphincs_a_static_${MODE}_${THASH})
        set(LIB_PATH $<TARGET_FILE:sphincs_a_static_${MODE}_${THASH}>)
        list(APPEND TARGET_STATIC_LIBS_PATH ${LIB_PATH})
    
    endforeach()

endforeach()

# Set custom target output name
set(SHARED_LIB_NAME "libpqmagic_sphincs_a_std.so")
set(STATIC_LIB_NAME "libpqmagic_sphincs_a_std.a")

# Set a custom target for shared library
add_custom_target(sphincs_a_target ALL
    COMMAND ${CMAKE_C_COMPILER} -shared -o ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
            -Wl,--whole-archive 
            ${TARGET_STATIC_LIBS_PATH} 
            $<TARGET_FILE:sm3>
            $<TARGET_FILE:fips202>
            $<TARGET_FILE:randombytes>
            -Wl,--no-whole-archive
    DEPENDS ${TARGET_STATIC_LIBS} sm3 fips202 randombytes
    COMMENT "Generating shared library ${SHARED_LIB_NAME}"
)


# Set mri script for archive library combination.
file(WRITE ${CURRENT_BUILD_DIR}/ar_script.mri "CREATE ${STATIC_LIB_NAME}\n")
foreach(lib ${TARGET_STATIC_LIBS})
    file(APPEND ${CURRENT_BUILD_DIR}/ar_script.mri "ADDLIB lib${lib}.a\n")
endforeach()
file(APPEND ${CURRENT_BUILD_DIR}/ar_script.mri "SAVE\nEND\n")

# Set a custom target for static library
add_custom_target(sphincs_a_static_target ALL
    COMMAND ${CMAKE_AR} -M < ${CURRENT_BUILD_DIR}/ar_script.mri
    DEPENDS ${TARGET_STATIC_LIBS}
    COMMENT "Generating static library ${STATIC_LIB_NAME}"
)

# Install lib.
install(FILES ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})
install(FILES ${CURRENT_BUILD_DIR}/${STATIC_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})

# Install api.h params.h config.h to include/sphincs_a dir
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/api.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/sphincs-a/std)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/params.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/sphincs-a/std)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION ${INSTALL_INCLUDE_DIR}/sig/sphincs-a/std)
