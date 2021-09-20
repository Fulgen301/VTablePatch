# SPDX-FileCopyrightText: 2021 George Tokmaji
# SPDX-License-Identifier: MIT

project(VTablePatchTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(..)

macro (addTest name)
    add_executable(${name} "${name}.cpp")
    add_test(NAME ${name} COMMAND ${name})
endmacro ()

addTest(PatchingWithPublicInheritance)
addTest(PatchingWithPrivateInheritance)
