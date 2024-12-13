cmake_minimum_required(VERSION 3.10)

set(CMAKE_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(CURRENT_BUILD_DIR ${CMAKE_BINARY_DIR}/kem/ml_kem/std)

# Include headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_PROJECT_ROOT} ${CMAKE_PROJECT_ROOT}/include ${CMAKE_PROJECT_ROOT}/utils)

# Find all source code.
file(GLOB ML_KEM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

# Compile all mode into static library.
set(TARGET_STATIC_LIBS "")
set(TARGET_STATIC_LIBS_PATH "")
foreach(MODE ${ML_KEM_MODES})
    # Add static lib.
    add_library(ml_kem_static_${MODE} STATIC ${ML_KEM_SOURCES})

    # Set ml_kem mode.
    target_compile_definitions(ml_kem_static_${MODE} PRIVATE ML_KEM_MODE=${MODE})
    if(USE_SHAKE)
    target_compile_definitions(ml_kem_static_${MODE} PRIVATE USE_SHAKE)
    endif()
    
    # Recored all modes target except for last one.
    list(APPEND TARGET_STATIC_LIBS ml_kem_static_${MODE})
    set(LIB_PATH $<TARGET_FILE:ml_kem_static_${MODE}>)
    list(APPEND TARGET_STATIC_LIBS_PATH ${LIB_PATH})
endforeach()

# Set custom target output name
set(SHARED_LIB_NAME "libpqmagic_ml_kem_std.so")
set(STATIC_LIB_NAME "libpqmagic_ml_kem_std.a")

if(USE_SM3)
# Set a custom target for shared library
add_custom_target(ml_kem_target ALL
    COMMAND ${CMAKE_C_COMPILER} -shared -o ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
            -Wl,--whole-archive 
            ${TARGET_STATIC_LIBS_PATH} 
            $<TARGET_FILE:sm3> 
            $<TARGET_FILE:randombytes> 
            -Wl,--no-whole-archive
    DEPENDS ${TARGET_STATIC_LIBS} sm3 randombytes
    COMMENT "Generating shared library ${SHARED_LIB_NAME}"
)
elseif(USE_SHAKE)
# Set a custom target for shared library
add_custom_target(ml_kem_target ALL
    COMMAND ${CMAKE_C_COMPILER} -shared -o ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
            -Wl,--whole-archive 
            ${TARGET_STATIC_LIBS_PATH} 
            $<TARGET_FILE:fips202> 
            $<TARGET_FILE:randombytes> 
            -Wl,--no-whole-archive
    DEPENDS ${TARGET_STATIC_LIBS} fips202 randombytes
    COMMENT "Generating shared library ${SHARED_LIB_NAME}"
)
else()
    message(FATAL_ERROR "Choose hash mode by -DUSE_SM3=ON or -DUSE_SHAKE=ON")
endif()

# Set mri script for archive library combination.
file(WRITE ${CURRENT_BUILD_DIR}/ar_script.mri "CREATE ${STATIC_LIB_NAME}\n")
foreach(lib ${TARGET_STATIC_LIBS})
    file(APPEND ${CURRENT_BUILD_DIR}/ar_script.mri "ADDLIB lib${lib}.a\n")
endforeach()
file(APPEND ${CURRENT_BUILD_DIR}/ar_script.mri "SAVE\nEND\n")

if(USE_SM3)
# Set a custom target for static library
add_custom_target(ml_kem_static_target ALL
    COMMAND ${CMAKE_AR} -M < ${CURRENT_BUILD_DIR}/ar_script.mri
    DEPENDS ${TARGET_STATIC_LIBS} sm3 randombytes
    COMMENT "Generating static library ${STATIC_LIB_NAME}"
)
elseif(USE_SHAKE)
# Set a custom target for static library
add_custom_target(ml_kem_static_target ALL
    COMMAND ${CMAKE_AR} -M < ${CURRENT_BUILD_DIR}/ar_script.mri
    DEPENDS ${TARGET_STATIC_LIBS} fips202 randombytes
    COMMENT "Generating static library ${STATIC_LIB_NAME}"
)
else()
    message(FATAL_ERROR "Choose hash mode by -DUSE_SM3=ON or -DUSE_SHAKE=ON")
endif()

# Install lib.
install(FILES ${CURRENT_BUILD_DIR}/${SHARED_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})
install(FILES ${CURRENT_BUILD_DIR}/${STATIC_LIB_NAME}
    DESTINATION ${INSTALL_LIB_DIR})

# Install api.h params.h to include/ml_kem dir
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/api.h DESTINATION ${INSTALL_INCLUDE_DIR}/kem/ml_kem)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/params.h DESTINATION ${INSTALL_INCLUDE_DIR}/kem/ml_kem)