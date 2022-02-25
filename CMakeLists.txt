
#
#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# CMake configuration for HACL.
#
# We only support Ninja as target, which is set in PreLoad.cmake, and require a
# modern CMake environment.
# WARNING: Preload.cmake is undocumented und apparently unfinished.
# The Ninja Multi-Config generator is only available since 3.17
# https://cmake.org/cmake/help/latest/generator/Ninja%20Multi-Config.html
cmake_minimum_required(VERSION 3.17)
if(WIN32)
    # Make sure we have visual studio enabled
    cmake_policy(SET CMP0091 NEW)
    # Avoid picking something that's not clang, unless the caller wants MSVC.
    if(NOT USE_MSVC)
        SET(CMAKE_C_COMPILER clang)
        SET(CMAKE_CXX_COMPILER clang++)
    else()
        SET(CMAKE_C_COMPILER cl.exe)
        SET(CMAKE_CXX_COMPILER cl.exe)
    endif(NOT USE_MSVC)
endif()

# Library version and name
project(hacl
        VERSION 0.1.0
        DESCRIPTION "The High Assurance Crypto Library"
        HOMEPAGE_URL "https://cryspen.com/hacl"
        LANGUAGES C CXX
)

# The assembly is different for MSVC ...
if(MSVC)
    enable_language(ASM_MASM)
else()
    enable_language(ASM)
endif()

set(hacl_VERSION_TWEAK "alpha.1")

# Load global config from exteral file.
# This file must be generated before running cmake with ./mach.py --configure
# If the build is invoked through ./mach.py, a separate configuration is not
# needed.
include(config/config.cmake)

# Constants used throughout hacl and the build.
include(config/constants.cmake)

# Set system processor to 32-bit.
# Note that this only works on intel for now.
if(CMAKE_C_FLAGS MATCHES ".*-m32.*")
    set(CMAKE_SYSTEM_PROCESSOR "i686")
endif()

# Configure C globally
# This defaults to C11 but C90 might be set on the outside.
# https://cmake.org/cmake/help/latest/prop_tgt/C_STANDARD.html#prop_tgt:C_STANDARD
if(NOT CMAKE_C_STANDARD)
    set(CMAKE_C_STANDARD 11)
endif(NOT CMAKE_C_STANDARD)
set(CMAKE_C_STANDARD_REQUIRED True)

# Read config from file
include(config/config.cmake)

# Configure different targets
# TODO: Set flags for MSVC
if(NOT MSVC)
    add_compile_options(
        # -Wall
        # -Wextra
        # -Wconversion
        # -Wsign-conversion
        # -Werror=gcc-compat
        $<$<CONFIG:DEBUG>:-g>
        $<$<CONFIG:DEBUG>:-Og>
        $<$<CONFIG:RELEASE>:-O3>  
    )
endif()

if(WIN32 AND NOT MSVC)
    # Enable everywhere for windows as long as libintvector.h is not included correctly.
    add_compile_options(
        -mavx
        -mavx2
    )
endif()

# Set target platform
# This is defined through the CMAKE_TOOLCHAIN_FILE. But CMAKE_OSX_ARCHITECTURES
# is not picked up correctly. So we set it again here.
if(DEFINED CMAKE_C_COMPILER_TARGET)
    if(${CMAKE_C_COMPILER_TARGET} STREQUAL x86_64-apple-darwin)
        set(CMAKE_SYSTEM_PROCESSOR x86_64)
        set(CMAKE_OSX_ARCHITECTURES x86_64)
    endif()
    if(${CMAKE_C_COMPILER_TARGET} STREQUAL s390x-linux-gnu)
        set(CMAKE_SYSTEM_PROCESSOR s390x)
        set(CMAKE_OSX_ARCHITECTURES s390x)
    endif()
endif()

# Set include paths
include_directories(${INCLUDE_PATHS} ${PROJECT_BINARY_DIR})

# Test the toolchain to get supported CPU features
include(config/toolchain.cmake)

if(${HACL_TARGET_OS} MATCHES linux)
    add_compile_options(
        -fPIC
    )
endif(${HACL_TARGET_OS} MATCHES linux)

# XXX: Investigate whether we can use CHECK_C_COMPILER_FLAG here at all

# Get command line options.
# This has to happen after the toolchain detection because it might disable
# toolchain features.
include(config/options.cmake)

# Sources are written by mach.py into the following lists
# - SOURCES_std: All regular files
# - SOURCES_vec128: Files that require vec128 hardware
# - SOURCES_vec256: Files that require vec256 hardware

# Remove files that require missing toolchain features
# and enable the features for compilation that are available.
if(TOOLCHAIN_CAN_COMPILE_VEC128)
    add_compile_options(
        -DHACL_CAN_COMPILE_VEC128
    )
    set(HACL_CAN_COMPILE_VEC128 1)
    ## We make separate compilation units (objects) for each hardware feature
    list(LENGTH SOURCES_vec128 SOURCES_VEC128_LEN)
    if(NOT SOURCES_VEC128_LEN EQUAL 0)
        set(HACL_VEC128_O ON)
        add_library(hacl_vec128 OBJECT ${SOURCES_vec128})
        target_include_directories(hacl_vec128 PRIVATE)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
            if(MSVC)
                # Nothing to do here. MSVC has it covered
            else()
                target_compile_options(hacl_vec128 PRIVATE
                    -msse2
                    -msse3
                    -msse4.1
                    -msse4.2
                )
            endif(MSVC)
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arm64v8")
            target_compile_options(hacl_vec128 PRIVATE
                -march=armv8-a+simd
            )
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "s390x")
            # In the case of IBMz, some of the vectorized functions are defined as
            # inline static rather than as macros, meaning we need to compile all
            # the files with the vector compilation options.
            # https://gcc.gnu.org/onlinedocs/gcc/S_002f390-and-zSeries-Options.html#S_002f390-and-zSeries-Options
            add_compile_options(
                -mzarch
                -mvx
                -mzvector
                -march=z14
            )
            target_compile_options(hacl_vec128 PRIVATE
                -mzarch
                -mvx
                -mzvector
                -march=z14
            )
        endif()
    endif()
endif()
if(TOOLCHAIN_CAN_COMPILE_VEC256)
    add_compile_options(
        -DHACL_CAN_COMPILE_VEC256
    )
    set(HACL_CAN_COMPILE_VEC256 1)
    ## We make separate compilation units (objects) for each hardware feature
    list(LENGTH SOURCES_vec256 SOURCES_VEC256_LEN)
    if(NOT SOURCES_VEC256_LEN EQUAL 0)
        set(HACL_VEC256_O ON)
        add_library(hacl_vec256 OBJECT ${SOURCES_vec256})
        target_include_directories(hacl_vec256 PRIVATE)
        # We really should only get here on x86 architectures. But let's make sure.
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
            if(MSVC)
                target_compile_options(hacl_vec256 PRIVATE
                    /arch:AVX
                    /arch:AVX2
                )
            else()
                target_compile_options(hacl_vec256 PRIVATE
                    -mavx
                    -mavx2
                )
            endif()
        endif()
    endif()
endif()
if(TOOLCHAIN_CAN_COMPILE_VALE)
    # Select the files for the target OS/Compiler
    if(WIN32 AND NOT MSVC)
        # On Windows with clang-cl (our default) we take the Linux assembly
        set(VALE_OBJECTS ${VALE_SOURCES_linux})
    else()
        set(VALE_OBJECTS ${VALE_SOURCES_${HACL_TARGET_OS}})
    endif()
    # Add SOURCES_vale to SOURCES_std as we don't need any
    # special compiler flags for it.
    list(APPEND SOURCES_std ${SOURCES_vale})
    set(HACL_CAN_COMPILE_VALE 1)
endif()
if(TOOLCHAIN_CAN_COMPILE_INLINE_ASM)
    # TODO: include inline assembly source code
endif()
if(TOOLCHAIN_CAN_COMPILE_INTRINSICS)
    # TODO: include intrinsics source code
endif()

# x64
# Set the architecture here. These come from the CMAKE_TOOLCHAIN_FILE
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    message(STATUS "Detected an x64 architecture")
    set(ARCHITECTURE intel)
    set(HACL_TARGET_ARCHITECTURE ${HACL_ARCHITECTURE_X64})
# x86
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32")
    message(STATUS "Detected an x86 architecture")
    set(ARCHITECTURE intel)
    set(HACL_TARGET_ARCHITECTURE ${HACL_ARCHITECTURE_X86})
# arm64
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arm64v8")
    message(STATUS "Detected an arm64 architecture")
    set(ARCHITECTURE arm)
    set(HACL_TARGET_ARCHITECTURE ${HACL_ARCHITECTURE_ARM64})
# arm32
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armel|armhf|armv7|arm32v7")
    message(STATUS "Detected an arm32 architecture")
    set(ARCHITECTURE arm)
    set(HACL_TARGET_ARCHITECTURE ${HACL_ARCHITECTURE_ARM32})
# s390x
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "s390x")
    message(STATUS "Detected an s390x (systemz) architecture")
    set(ARCHITECTURE arm)
    set(HACL_TARGET_ARCHITECTURE ${HACL_ARCHITECTURE_SYSTEMZ})
# unsupported architecture
else()
    message(FATAL_ERROR "Unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Write configuration
configure_file(config/Config.h.in config.h)

# Sanitizer
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()
if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

# Set library config and files
# Now combine everything into the hacl library
## Dynamic library
add_library(hacl SHARED ${SOURCES_std} ${VALE_OBJECTS})
if(TOOLCHAIN_CAN_COMPILE_VEC128 AND HACL_VEC128_O)
    add_dependencies(hacl hacl_vec128)
    target_link_libraries(hacl PRIVATE $<TARGET_OBJECTS:hacl_vec128>)
endif()
if(TOOLCHAIN_CAN_COMPILE_VEC256 AND HACL_VEC256_O)
    add_dependencies(hacl hacl_vec256)
    target_link_libraries(hacl PRIVATE $<TARGET_OBJECTS:hacl_vec256>)
endif()

## Static library
add_library(hacl_static STATIC ${SOURCES_std} ${VALE_OBJECTS})
if(TOOLCHAIN_CAN_COMPILE_VEC128 AND HACL_VEC128_O)
    target_sources(hacl_static PRIVATE $<TARGET_OBJECTS:hacl_vec128>)
endif()
if(TOOLCHAIN_CAN_COMPILE_VEC256 AND HACL_VEC256_O)
    target_sources(hacl_static PRIVATE $<TARGET_OBJECTS:hacl_vec256>)
endif()

# Install
## This allows package maintainers to control the install destination by setting
## the appropriate cache variables.
include(GNUInstallDirs)
set(CMAKE_INSTALL_MESSAGE LAZY)
install(TARGETS hacl_static hacl)
## Copy hacl headers
install(FILES ${PUBLIC_INCLUDES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hacl)
## Copy kremlin headers
install(DIRECTORY kremlin/include/kremlin/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kremlin
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY kremlin/kremlib/dist/minimal/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kremlin
        FILES_MATCHING PATTERN "*.h")
## Install vale headers
install(DIRECTORY vale/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vale
        FILES_MATCHING PATTERN "*.h")
## Install config.h
install(FILES build/config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hacl)

# Testing
# It's only one binary. Everything else is done with gtest arguments.
if(ENABLE_TESTS)
    # Get gtests
    include(FetchContent)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    # Get nlohmann json
    FetchContent_Declare(json
        URL https://github.com/nlohmann/json/archive/refs/tags/v3.10.3.zip
    )
    FetchContent_MakeAvailable(json)

    # CPU feature detection for tests
    add_library(hacl_cpu_features OBJECT ${PROJECT_SOURCE_DIR}/cpu-features/src/cpu-features.c)
    target_include_directories(hacl_cpu_features PUBLIC ${PROJECT_SOURCE_DIR}/cpu-features/include)

    foreach(TEST_FILE IN LISTS TEST_SOURCES)
        get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
        add_executable(${TEST_NAME}
            ${TEST_FILE}
        )
        # Set test directory. We don't do this right now to keep it portable.
        # target_compile_definitions(${TEST_NAME} PRIVATE
        #     TEST_DIR="${PROJECT_SOURCE_DIR}/tests/"
        # )
        add_dependencies(${TEST_NAME} hacl hacl_cpu_features)
        target_sources(${TEST_NAME} PRIVATE $<TARGET_OBJECTS:hacl_cpu_features>)
        target_link_libraries(${TEST_NAME} PRIVATE
            gtest_main
            hacl_static
            nlohmann_json::nlohmann_json
        )
        target_include_directories(${TEST_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/cpu-features/include)
    endforeach()
endif()
