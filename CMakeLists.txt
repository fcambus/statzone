#
# StatZone
# Copyright (c) 2012-2019, Frederic Cambus
# https://www.statdns.com
#
# Created: 2012-02-13
# Last Updated: 2019-01-03
#
# StatZone is released under the BSD 2-Clause license
# See LICENSE file for details.
#

cmake_minimum_required (VERSION 2.6)

project (statzone C)

include(CheckFunctionExists)
include(GNUInstallDirs)

# Additional include directories for compat functions
include_directories("compat")

set(SRC src/statzone.c src/strtolower.c)

add_definitions(-Wall -Wextra -std=c99 -pedantic)
add_executable(statzone ${SRC})

install(TARGETS statzone DESTINATION bin)
