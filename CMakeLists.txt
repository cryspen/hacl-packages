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
set(EVERCRYPT_COMPILE_VEC256 0)
set(EVERCRYPT_COMPILE_VEC128 0)

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

# Test the toolchain to get supported CPU features
include(config/toolchain.cmake)

# XXX: Investigate whether we can use CHECK_C_COMPILER_FLAG here at all

# Get command line options.
# This has to happen after the toolchain detection because it might disable
# toolchain features.
include(config/options.cmake)

# Select source files to compile depending on the configuration and the platform.
set(SOURCES "")
set(VEC128_SOURCES "")
set(VEC256_SOURCES "")

# Add all sources requested by the algorithms.
# XXX: We could simplifiy this in mach and write it out to config.cmake.
foreach(ALG ${ALGORITHMS})
    message(STATUS "Adding ${ALG}")
    list(APPEND SOURCES ${HACL_FILES_${ALG}})
endforeach()

# Remove duplicates from the list
list(REMOVE_DUPLICATES SOURCES)

# Remove files that require missing toolchain features
# and enable the features for compilation that are available.
# TODO: make compilation units for each flag
if(TOOLCHAIN_CAN_COMPILE_VEC128)
    ## We make separate compilation units (object files) for each hardware feature
    foreach(HACL_FILE ${CPU_FEATURE_vec128})
        if(${HACL_FILE} IN_LIST SOURCES)
            # Remove vec128 files from SOURCES and add them to VEC128_SOURCES
            list(APPEND VEC128_SOURCES ${HACL_FILE})
            list(REMOVE_ITEM SOURCES ${HACL_FILE})
        endif()
    endforeach()
    add_library(hacl_vec128 OBJECT ${VEC128_SOURCES})
    target_include_directories(hacl_vec128 PRIVATE
                                ${PROJECT_SOURCE_DIR}/include
                                ${PROJECT_SOURCE_DIR}/kremlin/include
                                ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                                )
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
        target_compile_options(hacl_vec128 PRIVATE
            -mavx
            -DHACL_CAN_COMPILE_VEC128
        )
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arm64v8")
        target_compile_options(hacl_vec128 PRIVATE
            -march=armv8-a+simd
            -DHACL_CAN_COMPILE_VEC128
        )
    endif()
else()
    message(STATUS "Disabling sources that require VEC128")
    foreach(HACL_FILE ${CPU_FEATURE_vec128})
        list(REMOVE_ITEM SOURCES ${HACL_FILE})
    endforeach()
endif()
if(NOT TOOLCHAIN_CAN_COMPILE_VEC256)
    message(STATUS "Disabling sources that require VEC256")
    foreach(HACL_FILE ${CPU_FEATURE_vec256})
        list(REMOVE_ITEM SOURCES ${HACL_FILE})
    endforeach()
else()
    # We really should only get here on x86 architectures. But let's make sure.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
        add_compile_options(
            -mavx2
            -DHACL_CAN_COMPILE_VEC256
        )
    endif()
endif()

# message(STATUS "SOURCES: ${SOURCES}")

# x64
# Set the architecture here. These come from the CMAKE_TOOLCHAIN_FILE
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    message(STATUS "Detected an x64 architecture")
    set(ARCHITECTURE intel)
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_X64})
    set(EVERCRYPT_ARCHITECTURE ${EVERCRYPT_ARCHITECTURE_X64})
    if(TOOLCHAIN_CAN_COMPILE_VALE)
        # TODO: include VALE source code
    endif()
    if(TOOLCHAIN_CAN_COMPILE_VEC128)
        add_compile_options(-mavx)
    endif()
    # We assume that all processors with AVX2 also support AVX
    if(TOOLCHAIN_CAN_COMPILE_VEC256)
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
## Now combine everything into the hacl library
## TODO: static and dynamic builds
add_library(hacl SHARED ${SOURCES})
if(TOOLCHAIN_CAN_COMPILE_VEC128)
    # XXX: move this further up to avoid the additional condition here.
    add_dependencies(hacl hacl_vec128)
    target_link_libraries(hacl PUBLIC hacl_vec128)
endif()
target_include_directories(hacl PRIVATE
                            ${PROJECT_SOURCE_DIR}/include
                            ${PROJECT_SOURCE_DIR}/kremlin/include
                            ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                            )


# Include config.h
target_include_directories(hacl PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )

# Testing
enable_testing()
if("blake2" IN_LIST ALGORITHMS)
    # TODO: read from config.json
    add_executable(test_blake2b ${PROJECT_SOURCE_DIR}/tests/blake2b.c)
    target_include_directories(test_blake2b PUBLIC
                                ${PROJECT_SOURCE_DIR}/include
                                ${PROJECT_SOURCE_DIR}/kremlin/include
                                ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                                )
    target_link_libraries(test_blake2b hacl)
    add_test(NAME blake2b COMMAND test_blake2b)
    add_executable(test_blake2s ${PROJECT_SOURCE_DIR}/tests/blake2s.c)
    target_include_directories(test_blake2s PUBLIC
                                ${PROJECT_SOURCE_DIR}/include
                                ${PROJECT_SOURCE_DIR}/kremlin/include
                                ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                                )
    if(TOOLCHAIN_CAN_COMPILE_VEC128)
        target_compile_options(test_blake2s PRIVATE
            -DHACL_CAN_COMPILE_VEC128
        )
    endif()
    target_link_libraries(test_blake2s hacl)
    add_test(NAME blake2s COMMAND test_blake2s)
endif()
if("p256" IN_LIST ALGORITHMS)
    add_executable(test_p256 ${PROJECT_SOURCE_DIR}/tests/p256.c)
    target_include_directories(test_p256 PUBLIC
                                ${PROJECT_SOURCE_DIR}/include
                                ${PROJECT_SOURCE_DIR}/kremlin/include
                                ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                                )
    target_link_libraries(test_p256 hacl)
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
