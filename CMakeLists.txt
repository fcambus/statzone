#
# StatZone 1.0.3
# Copyright (c) 2012-2020, Frederic Cambus
# https://www.statdns.com
#
# Created: 2012-02-13
# Last Updated: 2020-06-09
#
# StatZone is released under the BSD 2-Clause license
# See LICENSE file for details.
#

cmake_minimum_required (VERSION 2.6)

project (statzone C)

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

# uthash
find_path(UTHASH_INCLUDE_DIRS uthash.h)
include_directories(${UTHASH_INCLUDE_DIRS})

set(SRC src/statzone.c src/strtolower.c)

if(NOT HAVE_PLEDGE)
  set (SRC ${SRC} compat/pledge.c)
endif()

add_definitions(-D_GNU_SOURCE -Wall -Wextra -std=c99 -pedantic)
add_executable(statzone ${SRC})

install(TARGETS statzone DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES statzone.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1/)

enable_testing()
add_test(statzone statzone)
add_test(processing statzone ${PROJECT_SOURCE_DIR}/tests/arpa.zone)
