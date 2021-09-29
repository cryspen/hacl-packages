# CMake configuration for Evercrypt.
#
# We only support Ninja as target, which is set in PreLoad.cmake, and require a
# modern CMake environment.
# WARNING: Preload.cmake is undocumented und apparently unfinished.
# The Ninja Multi-Config generator is only available since 3.17
# https://cmake.org/cmake/help/latest/generator/Ninja%20Multi-Config.html
cmake_minimum_required(VERSION 3.17)

# Library version and name
project(evercrypt
        VERSION 1.0.0.0
        DESCRIPTION "The Evercrypt High Assurance Crypto Library"
        HOMEPAGE_URL "https://cryspen.com/evercrypt"
        )

# Load global config from exteral file.
# This file must be generated before running cmake with ./mach.py --configure
# If the build is invoked through ./mach.py, a separate configuration is not
# needed.
include(config/config.cmake)

# Configure C globally
# https://cmake.org/cmake/help/latest/prop_tgt/C_STANDARD.html#prop_tgt:C_STANDARD
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Set configuration constants
set(EVERCRYPT_ARCHITECTURE_UNKNOWN 0)
set(EVERCRYPT_ARCHITECTURE_X86 1)
set(EVERCRYPT_ARCHITECTURE_X64 2)
set(EVERCRYPT_ARCHITECTURE_ARM32 3)
set(EVERCRYPT_ARCHITECTURE_ARM64 4)
set(EVERCRYPT_ARCHITECTURE_SYSTEMZ 5)
set(EVERCRYPT_ARCHITECTURE_POWERPC64 6)

# Set variables ## TODO: drop
set(EVERCRYPT_COMPILE_VEC256 0)

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


# Test the toolchain to get supported CPU features
INCLUDE(CheckCCompilerFlag)
set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
## Check for gcc compiler bug 81300
if(NOT DEFINED BUG_81300)
    try_compile(BUG_81300
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/bug81300.c
                        # TODO: get the include paths from global variables
                        COMPILE_DEFINITIONS "-DCOMPILE_INTRINSICS \
                                             -march=native -O3\
                                             -I${PROJECT_SOURCE_DIR}/include \
                                             -I${PROJECT_SOURCE_DIR}/kremlin/include \
                                             -I${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal"
                )
endif()
message(STATUS "Bug 81300 check: ${BUG_81300}")
## Check for int128 support
if(NOT DEFINED INT128_SUPPORT)
    try_compile(INT128_SUPPORT
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/int128.c
                )
endif()
message(STATUS "int128 support: ${INT128_SUPPORT}")
## Check for explicit_bzero support
if(NOT DEFINED EXPLICIT_BZERO_SUPPORT)
    try_compile(EXPLICIT_BZERO_SUPPORT
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/explicit_bzero.c
                )
endif()
message(STATUS "explicit_bzero support: ${EXPLICIT_BZERO_SUPPORT}")

# XXX: This doesn't work! Use try_compile instead
CHECK_C_COMPILER_FLAG(-mavx TOOLCHAIN_HAS_AVX)
CHECK_C_COMPILER_FLAG(-mavx2 TOOLCHAIN_HAS_AVX2)
CHECK_C_COMPILER_FLAG(-msse TOOLCHAIN_HAS_SSE)
CHECK_C_COMPILER_FLAG(-msse2 TOOLCHAIN_HAS_SSE2)
CHECK_C_COMPILER_FLAG(-msse3 TOOLCHAIN_HAS_SSE3)
# We don't care about sse4a
# CHECK_C_COMPILER_FLAG(-msse4a TOOLCHAIN_HAS_SSE4A)
CHECK_C_COMPILER_FLAG(-msse4.1 TOOLCHAIN_HAS_SSE41)
CHECK_C_COMPILER_FLAG(-msse4.2 TOOLCHAIN_HAS_SSE42)
CHECK_C_COMPILER_FLAG(-maes TOOLCHAIN_HAS_AES)
CHECK_C_COMPILER_FLAG(-mpclmul TOOLCHAIN_HAS_PCLMUL)
CHECK_C_COMPILER_FLAG(-march=armv8-a+simd TOOLCHAIN_IS_ARMV8_WITH_SIMD)
CHECK_C_COMPILER_FLAG(-m32 TOOLCHAIN_HAS_32_SUPPORT)
CHECK_C_COMPILER_FLAG("-target arm64-apple-ios" TOOLCHAIN_HAS_IOS_TARGET)
CHECK_C_COMPILER_FLAG("-target arm64-apple-macos11" TOOLCHAIN_HAS_APPLE_ARM_TARGET)
CHECK_C_COMPILER_FLAG(-mcpu=power9 TOOLCHAIN_HAS_POWER9)

# Options for features.
# They all default to off and have to be explicitely enabled.
option(AVX "Enable code requiring AVX")
option(AVX2 "Enable code requiring AVX2")

# Select source files to compile depending on the configuration and the platform.
set(SOURCES "")

foreach(ALG ${ALGORITHMS})
    message(STATUS "Adding ${ALG}")
    list(APPEND SOURCES ${HACL_FILES_${ALG}})
endforeach()

# Remove duplicates from the list
list(REMOVE_DUPLICATES SOURCES)

set(TOOLCHAIN_HAS_AVX2 OFF) # XXX: FOR TESTING ONLY
set(TOOLCHAIN_HAS_AVX OFF) # XXX: FOR TESTING ONLY
# Remove files that require missing toolchain features
# and enable the features for compilation that are available.
# TODO: make compilation units for each flag
if(NOT TOOLCHAIN_HAS_AVX)
    message(STATUS "Disabling sources that require AVX")
    foreach(HACL_FILE ${CPU_FEATURE_avx})
        list(REMOVE_ITEM SOURCES ${HACL_FILE})
    endforeach()
else()
    add_compile_options(
        -mavx
        -DHACL_CAN_COMPILE_VEC256
    )
endif()
if(NOT TOOLCHAIN_HAS_AVX2)
    message(STATUS "Disabling sources that require AVX2")
    foreach(HACL_FILE ${CPU_FEATURE_avx2})
        list(REMOVE_ITEM SOURCES ${HACL_FILE})
    endforeach()
else()
    add_compile_options(
        -mavx2
        -DHACL_CAN_COMPILE_VEC256
    )
endif()

# message(STATUS "SOURCES: ${SOURCES}")

# x64
# Set the architecture here. These come from the CMAKE_TOOLCHAIN_FILE
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    message(STATUS "Detected an x64 architecture")
    set(ARCHITECTURE intel)
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_X64})
    set(EVERCRYPT_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_X64})
    if(AVX)
        add_compile_options(-mavx)
    endif()
    # We assume that all processors with AVX2 also support AVX
    if(AVX2)
        set(EVERCRYPT_COMPILE_VEC256 1)
        add_compile_options(-mavx2)
        set(SOURCES ${SOURCES}
        ${PROJECT_SOURCE_DIR}/src/Hacl_Blake2b_256.c
            )
    endif()
# x86
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32")
    message(STATUS "Detected an x86 architecture")
    set(ARCHITECTURE intel)
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_X86})
    set(EVERCRYPT_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_X86})
# arm64
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arm64v8")
    message(STATUS "Detected an arm64 architecture")
    set(ARCHITECTURE arm)
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_ARM64})
    set(EVERCRYPT_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_ARM64})
# arm32
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armel|armhf|armv7|arm32v7")
    message(STATUS "Detected an arm32 architecture")
    set(ARCHITECTURE arm)
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_ARM32})
    set(EVERCRYPT_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_ARM32})
# unsupported architecture
else()
    message(FATAL_ERROR "Unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Write configuration
configure_file(config/Config.h.in config.h)

# Set library config and files
add_library(evercrypt STATIC ${SOURCES})
target_include_directories(evercrypt PRIVATE
                            ${PROJECT_SOURCE_DIR}/include
                            ${PROJECT_SOURCE_DIR}/kremlin/include
                            ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                            )


# Include config.h
target_include_directories(evercrypt PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )

# Testing
enable_testing()
if("blake2" IN_LIST ALGORITHMS)
    add_executable(test_blake2b ${PROJECT_SOURCE_DIR}/tests/blake2b.c)
    target_include_directories(test_blake2b PUBLIC
                                ${PROJECT_SOURCE_DIR}/include
                                ${PROJECT_SOURCE_DIR}/kremlin/include
                                ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                                )
    target_link_libraries(test_blake2b evercrypt)
    add_test(NAME blake2b COMMAND test_blake2b)
endif()
if("p256" IN_LIST ALGORITHMS)
    add_executable(test_p256 ${PROJECT_SOURCE_DIR}/tests/p256.c)
    target_include_directories(test_p256 PUBLIC
                                ${PROJECT_SOURCE_DIR}/include
                                ${PROJECT_SOURCE_DIR}/kremlin/include
                                ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                                )
    target_link_libraries(test_p256 evercrypt)
    add_test(NAME p256 COMMAND test_p256)
endif()

# Hardware detection
if(ARCHITECTURE MATCHES "intel")
    message("Adding ${PROJECT_SOURCE_DIR}/hw-detection/hw-detection.c")
    add_executable(hw-detection ${PROJECT_SOURCE_DIR}/src/hw-detection/hw-detection.c
                                ${PROJECT_SOURCE_DIR}/src/hw-detection/cpu-features.c
                    )
    target_include_directories(hw-detection PUBLIC
                                ${PROJECT_SOURCE_DIR}/include
                                )
endif()
