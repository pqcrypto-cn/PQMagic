
if (ENABLE_GMP_BUILD)
  # Download and build own libgmp version
  if (POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
  endif()
  SET(GMP_BUILD_CONFIG_ARGS "" CACHE STRING "Some user-specified gmp config options")
  option(ENABLE_GMP_STATIC "Option to statically link. Default is dynamic linking" OFF)

  if (ENABLE_GMP_STATIC)
    set(GMP_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
  else()
    set(GMP_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
  endif()

  message("${GMP_BUILD_CONFIG_ARGS}")
  include(ExternalProject)
  find_program(MAKE_EXE NAMES make gmake nmake)
  set(libgmp_INSTALL_DIR "${CMAKE_BINARY_DIR}/libgmp")
  ExternalProject_Add(libgmp_external
    PREFIX ${libgmp_INSTALL_DIR}
    URL               https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz
    URL_HASH          SHA256=fd4829912cddd12f84181c3451cc752be224643e87fac497b69edddadc49b4f2
    CONFIGURE_COMMAND ${libgmp_INSTALL_DIR}/src/libgmp_external/configure --prefix=${libgmp_INSTALL_DIR} ${GMP_BUILD_CONFIG_ARGS}
    BUILD_COMMAND     ${MAKE_EXE} -j8
    INSTALL_COMMAND   ${MAKE_EXE} install
  )

  set(GMP ${libgmp_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gmp${GMP_LIB_SUFFIX})
  include_directories(${libgmp_INSTALL_DIR}/include)
else()
  # use system gmp version
  find_library(GMP gmp)
  find_path(GMP_INCLUDE gmp.h)
  include_directories(${GMP_INCLUDE})
endif()