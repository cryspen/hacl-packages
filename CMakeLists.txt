# CMake configuration for Evercrypt.
#
# We only support Ninja as target, which is set in PreLoad.cmake, and require a
# modern CMake environment.
# The Ninja Multi-Config generator is only available since 3.17
# https://cmake.org/cmake/help/latest/generator/Ninja%20Multi-Config.html
cmake_minimum_required(VERSION 3.21)

# Library version and name
project(evercrypt
        VERSION 1.0.0.0
        DESCRIPTION "The Evercrypt High Assurance Crypto Library"
        HOMEPAGE_URL "https://cryspen.com/evercrypt"
        )

# Configure C globally
# https://cmake.org/cmake/help/latest/prop_tgt/C_STANDARD.html#prop_tgt:C_STANDARD
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Set configuration constants
set(EVERCRYPT_TARGET_ARCHITECTURE_UNKNOWN 0)
set(EVERCRYPT_TARGET_ARCHITECTURE_X86 1)
set(EVERCRYPT_TARGET_ARCHITECTURE_X64 2)
set(EVERCRYPT_TARGET_ARCHITECTURE_ARM32 3)
set(EVERCRYPT_TARGET_ARCHITECTURE_ARM64 4)
set(EVERCRYPT_TARGET_ARCHITECTURE_SYSTEMZ 5)
set(EVERCRYPT_TARGET_ARCHITECTURE_POWERPC64 6)

## Set variables
set(EVERCRYPT_COMPILE_VEC256 0)

# Configure different targets
add_compile_options(
    -Wall
    -Wextra
    -Wconversion
    -Wsign-conversion
    $<$<CONFIG:DEBUG>:-g>
    $<$<CONFIG:DEBUG>:-Og>
    $<$<CONFIG:RELEASE>:-O3>  
)

# Options for features.
# They all default to off and have to be explicitely enabled.
option(AVX "Enable code requiring AVX")
option(AVX2 "Enable code requiring AVX2")

# Select source files to compile depending on the configuration and the platform.
set(SOURCES ${PROJECT_SOURCE_DIR}/src/Hacl_Blake2b_32.c
            ${PROJECT_SOURCE_DIR}/src/Lib_Memzero0.c
    )

# x64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    message(STATUS "Detected an x64 architecture")
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_TARGET_ARCHITECTURE_X64})
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
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_TARGET_ARCHITECTURE_X86})
# arm64
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arm64v8")
    message(STATUS "Detected an arm64 architecture")
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_TARGET_ARCHITECTURE_ARM64})
# arm32
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armel|armhf|armv7|arm32v7")
    message(STATUS "Detected an arm32 architecture")
    set(EVERCRYPT_TARGET_ARCHITECTURE ${EVERCRYPT_TARGET_ARCHITECTURE_ARM32})
# unsupported architecture
else()
    message(FATAL_ERROR "Unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Write configuration
configure_file(Config.h.in Config.h)

# Set library config and files
add_library(evercrypt STATIC ${SOURCES})
target_include_directories(evercrypt PRIVATE
                            ${PROJECT_SOURCE_DIR}/include
                            ${PROJECT_SOURCE_DIR}/kremlin/include
                            ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                            )


# Include Config.h
target_include_directories(evercrypt PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )

# Testing
add_executable(test_blake2b ${PROJECT_SOURCE_DIR}/tests/blake2b.c)
target_include_directories(test_blake2b PUBLIC
                            ${PROJECT_SOURCE_DIR}/include
                            ${PROJECT_SOURCE_DIR}/kremlin/include
                            ${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal
                            )
target_link_libraries(test_blake2b evercrypt)

enable_testing()
add_test(NAME blake2b COMMAND test_blake2b)
