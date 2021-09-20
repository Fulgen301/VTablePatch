# SPDX-FileCopyrightText: 2021 George Tokmaji
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.18)

project(VTablePatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_PROJECT_NAME STREQUAL ${PROJECT_NAME})
    include(CTest)

    if (BUILD_TESTING)
        enable_testing()
        add_subdirectory(tests)
    endif ()
endif ()
