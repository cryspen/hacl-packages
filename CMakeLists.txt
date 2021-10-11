# CMake configuration for HACL.
#
# We only support Ninja as target, which is set in PreLoad.cmake, and require a
# modern CMake environment.
# WARNING: Preload.cmake is undocumented und apparently unfinished.
# The Ninja Multi-Config generator is only available since 3.17
# https://cmake.org/cmake/help/latest/generator/Ninja%20Multi-Config.html
cmake_minimum_required(VERSION 3.17)

# Library version and name
project(hacl
        VERSION 1.0.0.0
        DESCRIPTION "The HACL High Assurance Crypto Library"
        HOMEPAGE_URL "https://cryspen.com/hacl"
        )

# Dependencies
# gtests are used for testing
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Load global config from exteral file.
# This file must be generated before running cmake with ./mach.py --configure
# If the build is invoked through ./mach.py, a separate configuration is not
# needed.
include(config/config.cmake)

# Constants used throughout hacl and the build.
include(config/constants.cmake)

# Configure C globally
# https://cmake.org/cmake/help/latest/prop_tgt/C_STANDARD.html#prop_tgt:C_STANDARD
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)


# Set variables ## TODO: drop
set(HACL_COMPILE_VEC256 0)
set(HACL_COMPILE_VEC128 0)

# Read config from file
include(config/config.cmake)

# Configure different targets
add_compile_options(
    # -Wall
    # -Wextra
    # -Wconversion
    # -Wsign-conversion
    $<$<CONFIG:DEBUG>:-g>
    $<$<CONFIG:DEBUG>:-Og>
    $<$<CONFIG:RELEASE>:-O3>  
)

# Set target platform
# This is defined through the CMAKE_TOOLCHAIN_FILE. But CMAKE_OSX_ARCHITECTURES
# is not picked up correctly. So we set it again here.
if(DEFINED CMAKE_C_COMPILER_TARGET)
    if(${CMAKE_C_COMPILER_TARGET} STREQUAL x86_64-apple-darwin)
        set(CMAKE_SYSTEM_PROCESSOR x86_64)
        set(CMAKE_OSX_ARCHITECTURES x86_64)
    endif()
endif()

# Set include paths
include_directories(${INCLUDE_PATHS} ${PROJECT_BINARY_DIR})

# Test the toolchain to get supported CPU features
include(config/toolchain.cmake)

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
# message(FATAL_ERROR "vec128: ${TOOLCHAIN_CAN_COMPILE_VEC128}")
if(TOOLCHAIN_CAN_COMPILE_VEC128)
    add_compile_options(
        -DHACL_CAN_COMPILE_VEC128
    )
    ## We make separate compilation units (static libraries) for each hardware feature
    list(LENGTH SOURCES_vec128 SOURCES_VEC128_LEN)
    if(NOT SOURCES_VEC128_LEN EQUAL 0)
        set(HACL_VEC128_O ON)
        add_library(hacl_vec128 STATIC ${SOURCES_vec128})
        target_include_directories(hacl_vec128 PRIVATE)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
            target_compile_options(hacl_vec128 PRIVATE
                -mavx
            )
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arm64v8")
            target_compile_options(hacl_vec128 PRIVATE
                -march=armv8-a+simd
            )
        endif()
    endif()
endif()
if(TOOLCHAIN_CAN_COMPILE_VEC256)
    add_compile_options(
        -DHACL_CAN_COMPILE_VEC256
    )
    ## We make separate compilation units (static libraries) for each hardware feature
    list(LENGTH SOURCES_vec256 SOURCES_VEC256_LEN)
    if(NOT SOURCES_VEC256_LEN EQUAL 0)
        set(HACL_VEC256_O ON)
        add_library(hacl_vec256 STATIC ${SOURCES_vec256})
        target_include_directories(hacl_vec256 PRIVATE)
        # We really should only get here on x86 architectures. But let's make sure.
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
            target_compile_options(hacl_vec256 PRIVATE
                -mavx2
            )
        endif()
    endif()
endif()
if(TOOLCHAIN_CAN_COMPILE_VALE)
    # TODO: include VALE source code
endif()
if(TOOLCHAIN_CAN_COMPILE_INLINE_ASM)
    # TODO: include inline assembly source code
endif()
if(TOOLCHAIN_CAN_COMPILE_INTRINSICS)
    # TODO: include intrinsics source code
endif()

# message(STATUS "SOURCES: ${SOURCES}")

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
# unsupported architecture
else()
    message(FATAL_ERROR "Unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Write configuration
configure_file(config/Config.h.in config.h)

# Set library config and files
## Now combine everything into the hacl library
## TODO: static and dynamic builds
add_library(hacl SHARED ${SOURCES_std})
if(TOOLCHAIN_CAN_COMPILE_VEC128 AND HACL_VEC128_O)
    add_dependencies(hacl hacl_vec128)
    target_link_libraries(hacl PUBLIC hacl_vec128)
endif()
if(TOOLCHAIN_CAN_COMPILE_VEC256 AND HACL_VEC256_O)
    add_dependencies(hacl hacl_vec256)
    target_link_libraries(hacl PUBLIC hacl_vec256)
endif()
target_include_directories(hacl PRIVATE)

# Testing
# It's only one binary. Everything else is done with gtest arguments.
foreach(TEST_FILE IN LISTS TEST_SOURCES)
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    # message(STATUS "Compiling test ${TEST_FILE} into ${TEST_NAME}")
    add_executable(${TEST_NAME}
        ${TEST_FILE}
    )
    target_link_libraries(${TEST_NAME}
        gtest_main
        hacl
    )
endforeach()

# Hardware detection
if(ARCHITECTURE MATCHES "intel")
    message("Adding ${PROJECT_SOURCE_DIR}/hw-detection/hw-detection.c")
    add_executable(hw-detection ${PROJECT_SOURCE_DIR}/src/hw-detection/hw-detection.c
                                ${PROJECT_SOURCE_DIR}/src/hw-detection/cpu-features.c
                    )
    target_include_directories(hw-detection PUBLIC)
endif()
