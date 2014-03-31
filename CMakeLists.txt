project(pacrunner-cutes)
cmake_minimum_required(VERSION 2.8)

find_package(PkgConfig)
find_package (Threads)

option(ENABLE_MULTIARCH "Enable support for multi-arch distros (lib64)" OFF)
IF(ENABLE_MULTIARCH)
  IF(CMAKE_SIZEOF_VOID_P EQUAL 4)
    SET(LIB_SUFFIX "")
  ELSE(CMAKE_SIZEOF_VOID_P EQUAL 4)
    SET(LIB_SUFFIX 64)
  ENDIF(CMAKE_SIZEOF_VOID_P EQUAL 4)
ELSE()
  SET(LIB_SUFFIX "")
ENDIF()

set(prefix ${CMAKE_INSTALL_PREFIX})
set(DST_LIB lib${LIB_SUFFIX})
set(PACRUNNER_DATA_PATH ${prefix}/share/pacrunner)

set(CMAKE_CXX_FLAGS 
  "${CMAKE_CXX_FLAGS} -Wall -O2 -feliminate-unused-debug-types -std=c++0x"
  )

pkg_check_modules(COR cor REQUIRED)
pkg_check_modules(CUTES cutes REQUIRED)
pkg_check_modules(PACRUNNER pacrunner-1.0 REQUIRED)
pkg_check_modules(GLIB glib-2.0)

include_directories(
  ${COR_INCLUDE_DIRS}
  ${CUTES_INCLUDE_DIRS}
  ${PACRUNNER_INCLUDE_DIRS}
  ${GLIB_INCLUDE_DIRS}
)

link_directories(
  ${COR_LIBRARY_DIRS}
  ${CUTES_LIBRARY_DIRS}
  ${PACRUNNER_LIBRARY_DIRS}
  ${GLIB_LIBRARY_DIRS}
)

add_subdirectory(src)
