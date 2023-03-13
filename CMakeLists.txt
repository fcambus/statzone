#
# StatZone 1.1.1
# Copyright (c) 2012-2023, Frederic Cambus
# https://www.statdns.com
#
# Created: 2012-02-13
# Last Updated: 2023-03-13
#
# StatZone is released under the BSD 2-Clause license.
# See LICENSE file for details.
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(statzone CXX)

include(CheckFunctionExists)
include(GNUInstallDirs)

# Conditional build options
set(ENABLE_SECCOMP 0 CACHE BOOL "Enable building with seccomp")

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

set(SRC src/statzone.cpp src/strtolower.cpp)

add_definitions(-Wall -Wextra -pedantic)
add_executable(statzone ${SRC})

install(TARGETS statzone DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES man/statzone.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1/)

enable_testing()
add_test(statzone statzone)
add_test(processing statzone ${PROJECT_SOURCE_DIR}/tests/arpa.zone)
