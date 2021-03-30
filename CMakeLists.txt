#
# StatZone 1.0.5
# Copyright (c) 2012-2021, Frederic Cambus
# https://www.statdns.com
#
# Created: 2012-02-13
# Last Updated: 2021-03-30
#
# StatZone is released under the BSD 2-Clause license
# See LICENSE file for details.
#

cmake_minimum_required (VERSION 2.6)

project (statzone CXX)

include(CheckFunctionExists)
include(GNUInstallDirs)

# Conditional build options
set(ENABLE_SECCOMP 0
    CACHE BOOL "Enable building with seccomp")

# Check if system has pledge
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_OPENBSD_SOURCE)
check_function_exists(pledge HAVE_PLEDGE)

if(ENABLE_SECCOMP)
  # Check if system has seccomp
  message(STATUS "Looking for seccomp")
  find_path(SECCOMP NAMES "linux/seccomp.h")
  if(SECCOMP)
    message(STATUS "Looking for seccomp - found")
    add_definitions(-DHAVE_SECCOMP)
  else()
    message(STATUS "Looking for seccomp - not found")
  endif()
endif(ENABLE_SECCOMP)

# Additional include directories for compat functions
include_directories("compat")

set(SRC src/statzone.cpp src/strtolower.cpp)

if(NOT HAVE_PLEDGE)
  set (SRC ${SRC} compat/pledge.cpp)
endif()

add_definitions(-Wall -Wextra -std=c++11 -pedantic)
add_executable(statzone ${SRC})

install(TARGETS statzone DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES statzone.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1/)

enable_testing()
add_test(statzone statzone)
add_test(processing statzone ${PROJECT_SOURCE_DIR}/tests/arpa.zone)
