#
# Copyright 2022 Cryspen Sarl
#
# Licensed under the Apache License, Version 2.0 or MIT.
# * http://www.apache.org/licenses/LICENSE-2.0
# * http://opensource.org/licenses/MIT
#
# CMake configuration for HACL.
#
# The Ninja Multi-Config generator is only available since 3.17
# https://cmake.org/cmake/help/latest/generator/Ninja%20Multi-Config.html
# cmake_minimum_required(VERSION 3.17)
# But this script can be used standalone without mach where older cmake versions
# are supported.
cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0012 NEW)
cmake_policy(SET CMP0042 NEW)

if(WIN32)
    # Make sure we have visual studio enabled
    cmake_policy(SET CMP0091 NEW)

    # Avoid picking something that's not clang, unless the caller wants MSVC.
    if(NOT USE_MSVC)
        SET(CMAKE_C_COMPILER clang)
        SET(CMAKE_CXX_COMPILER clang++)
    else()
        SET(CMAKE_C_COMPILER cl)
        SET(CMAKE_CXX_COMPILER cl)
    endif(NOT USE_MSVC)
endif()

# Library version and name
project(hacl
    VERSION 0.6.0
    DESCRIPTION "The High Assurance Crypto Library"
    LANGUAGES C CXX
)

set(PROJECT_EXPORT_NAME "hacl")

# The assembly is different for MSVC ...
if(MSVC)
    enable_language(ASM_MASM)
else()
    enable_language(ASM)
endif()

set(hacl_VERSION_TWEAK "")

# Load global config from external file.
# For a Clang build, this file can be generated before running cmake with
# ./mach.py --configure
# If the build is invoked through ./mach.py, a separate configuration is not
# needed.
# We copy a default config from config/default_config.cmake or
# config/default_config_msvc.cmake
if(NOT EXISTS ${PROJECT_SOURCE_DIR}/build/config.cmake)
    if(USE_MSVC)
        configure_file(${PROJECT_SOURCE_DIR}/config/default_config_msvc.cmake ${PROJECT_SOURCE_DIR}/build/config.cmake COPYONLY)
    else()
        configure_file(${PROJECT_SOURCE_DIR}/config/default_config.cmake ${PROJECT_SOURCE_DIR}/build/config.cmake COPYONLY)
    endif()
endif()

# Now include the config.
include(${PROJECT_SOURCE_DIR}/build/config.cmake)

# Constants used throughout hacl and the build.
include(config/constants.cmake)

# Set system processor to 32-bit.
# Note that this only works on intel for now.
if(CMAKE_C_FLAGS MATCHES ".*-m32.*")
    set(CMAKE_SYSTEM_PROCESSOR "i686")
    set(BENCHMARK_BUILD_32_BITS ON)
endif()

# Configure C globally
# This defaults to C11 but C90 might be set on the outside.
# https://cmake.org/cmake/help/latest/prop_tgt/C_STANDARD.html#prop_tgt:C_STANDARD
if(NOT CMAKE_C_STANDARD)
    set(CMAKE_C_STANDARD 11)
endif(NOT CMAKE_C_STANDARD)

set(CMAKE_C_STANDARD_REQUIRED True)

# Read config from file
include(build/config.cmake)

# Configure different targets
if(MSVC)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:C,CXX>:/Ob3>
    )
else()
    add_compile_options(
        # -Wall
        # -Wextra
        # -pedantic
        # -Wconversion
        # -Wsign-conversion
        $<$<CONFIG:DEBUG>:-g>
        $<$<CONFIG:DEBUG>:-Og>
        $<$<CONFIG:RELEASE>:-O3>
    )
endif()

if(WIN32)
    # Enable AVX and AVX2 everywhere for Windows as long as libintvector.h is not included correctly.
    if(MSVC)
        add_compile_options(
            $<$<COMPILE_LANGUAGE:C,CXX>:/arch:AVX>
            $<$<COMPILE_LANGUAGE:C,CXX>:/arch:AVX2>
        )
    else()
        # On Windows with clang-cl (our default) we take the Linux assembly
        add_compile_options(
            -mavx
            -mavx2
        )
    endif()
endif()

# Set include paths
include_directories(${INCLUDE_PATHS} ${PROJECT_BINARY_DIR})

# Test the toolchain to get supported CPU features
include(config/toolchain.cmake)

if(NOT EXPLICIT_BZERO_SUPPORT)
    set(LINUX_NO_EXPLICIT_BZERO 1)
    message(STATUS "LINUX_NO_EXPLICIT_BZERO: ${LINUX_NO_EXPLICIT_BZERO}")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES Linux)
    add_compile_options(
        -fPIC
    )
endif(${CMAKE_SYSTEM_NAME} MATCHES Linux)

# XXX: Investigate whether we can use CHECK_C_COMPILER_FLAG here at all

# Get command line options.
# This has to happen after the toolchain detection because it might disable
# toolchain features.
include(config/options.cmake)

# Write out config to file
if(${TOOLCHAIN_CAN_COMPILE_VEC128})
    write_file(${PROJECT_SOURCE_DIR}/build/Makefile.include
        "TOOLCHAIN_CAN_COMPILE_VEC128=${TOOLCHAIN_CAN_COMPILE_VEC128}\n"
        APPEND)
endif(${TOOLCHAIN_CAN_COMPILE_VEC128})

if(${TOOLCHAIN_CAN_COMPILE_VEC256})
    write_file(${PROJECT_SOURCE_DIR}/build/Makefile.include
        "TOOLCHAIN_CAN_COMPILE_VEC256=${TOOLCHAIN_CAN_COMPILE_VEC256}\n"
        APPEND)
endif(${TOOLCHAIN_CAN_COMPILE_VEC256})

if(${TOOLCHAIN_CAN_COMPILE_VALE})
    write_file(${PROJECT_SOURCE_DIR}/build/Makefile.include
        "TOOLCHAIN_CAN_COMPILE_VALE=${TOOLCHAIN_CAN_COMPILE_VALE}\n"
        APPEND)
endif(${TOOLCHAIN_CAN_COMPILE_VALE})

# Coverage
if(ENABLE_COVERAGE)
    message(STATUS "Coverage instrumentation enabled")
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate -fcoverage-mapping)
endif()

# Sanitizer
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

if(ENABLE_MSAN)
    add_compile_options(-fsanitize=memory -fsanitize-memory-track-origins)
    add_link_options(-fsanitize=memory)
endif()

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

    # # We make separate compilation units (objects) for each hardware feature
    list(LENGTH SOURCES_vec128 SOURCES_VEC128_LEN)

    if(NOT SOURCES_VEC128_LEN EQUAL 0)
        set(HACL_VEC128_O ON)
        if(TOOLCHAIN_CAN_COMPILE_VALE)
            # HPKE requires vale and vec128
            list (APPEND SOURCES_vec128 ${SOURCES_vec128_vale})
        endif(TOOLCHAIN_CAN_COMPILE_VALE)
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

    # # We make separate compilation units (objects) for each hardware feature
    list(LENGTH SOURCES_vec256 SOURCES_VEC256_LEN)

    if(NOT SOURCES_VEC256_LEN EQUAL 0)
        set(HACL_VEC256_O ON)
        if(TOOLCHAIN_CAN_COMPILE_VALE)
            # HPKE requires vale and vec256
            list (APPEND SOURCES_vec256 ${SOURCES_vec256_vale})
        endif(TOOLCHAIN_CAN_COMPILE_VALE)
        add_library(hacl_vec256 OBJECT ${SOURCES_vec256})
        target_include_directories(hacl_vec256 PRIVATE)

        # We really should only get here on x86 architectures. But let's make sure.
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86|x86_64|amd64|AMD64")
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
        set(VALE_OBJECTS ${VALE_SOURCES_mingw})
    else()
        set(VALE_OBJECTS ${VALE_SOURCES_${HACL_TARGET_OS}})
    endif()

    # Add SOURCES_vale to SOURCES_std as we don't need any
    # special compiler flags for it.
    list(APPEND SOURCES_std ${SOURCES_vale})
    list(APPEND SOURCES_std ${SOURCES_std_vale})
    message(STATUS "Detected vale support")
    set(HACL_CAN_COMPILE_VALE 1)
endif()

if(TOOLCHAIN_CAN_COMPILE_INLINE_ASM)
    message(STATUS "Detected inline assembly support")
    set(HACL_CAN_COMPILE_INLINE_ASM 1)
endif()

if(TOOLCHAIN_CAN_COMPILE_INTRINSICS)
    message(STATUS "Detected intrinsics support")
    set(HACL_CAN_COMPILE_INTRINSICS 1)
endif()

# x64
# Set the architecture here. These come from the CMAKE_TOOLCHAIN_FILE
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    message(STATUS "Detected an x64 architecture")
    set(ARCHITECTURE intel)
    set(HACL_TARGET_ARCHITECTURE ${HACL_ARCHITECTURE_X64})

# x86
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86")
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

# Set library config and files
# Now combine everything into the hacl library
# # Dynamic library
add_library(hacl SHARED ${SOURCES_std} ${VALE_OBJECTS})
if(NOT MSVC)
    target_compile_options(hacl PRIVATE -Wall -Wextra -pedantic)
endif()

if(TOOLCHAIN_CAN_COMPILE_VEC128 AND HACL_VEC128_O)
    add_dependencies(hacl hacl_vec128)
    target_link_libraries(hacl PRIVATE $<TARGET_OBJECTS:hacl_vec128>)
endif()

if(TOOLCHAIN_CAN_COMPILE_VEC256 AND HACL_VEC256_O)
    add_dependencies(hacl hacl_vec256)
    target_link_libraries(hacl PRIVATE $<TARGET_OBJECTS:hacl_vec256>)
endif()

# # Static library
add_library(hacl_static STATIC ${SOURCES_std} ${VALE_OBJECTS})

if(TOOLCHAIN_CAN_COMPILE_VEC128 AND HACL_VEC128_O)
    target_sources(hacl_static PRIVATE $<TARGET_OBJECTS:hacl_vec128>)
endif()

if(TOOLCHAIN_CAN_COMPILE_VEC256 AND HACL_VEC256_O)
    target_sources(hacl_static PRIVATE $<TARGET_OBJECTS:hacl_vec256>)
endif()

if(BUILD_LIBCRUX)
    add_library(libcrux_static STATIC ${LIBCRUX_SOURCES})
    if(NOT MSVC)
        target_compile_options(libcrux_static PRIVATE -Wall -Wextra -pedantic -Wshadow -Wunused-function)
    endif()
endif()

# Install
# # This allows package maintainers to control the install destination by setting
# # the appropriate cache variables.
set(CMAKE_INSTALL_LIBDIR lib)
include(GNUInstallDirs)
set(CMAKE_INSTALL_MESSAGE LAZY)
install(TARGETS hacl_static hacl
    EXPORT ${PROJECT_EXPORT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Export the cmake config for use in downstream libraries
export(
    EXPORT ${PROJECT_EXPORT_NAME}
    FILE ${PROJECT_BINARY_DIR}/${PROJECT_EXPORT_NAME}Config.cmake
)

# install the cmake config for use in downsteam libraries
install(
    EXPORT ${PROJECT_EXPORT_NAME}
    FILE ${PROJECT_EXPORT_NAME}Config.cmake
    DESTINATION lib/cmake/${PROJECT_EXPORT_NAME}/${PROJECT_VERSION}
)

# # Copy hacl headers
install(FILES ${PUBLIC_INCLUDES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hacl)

# # Copy karamel headers
install(DIRECTORY karamel/include/krml/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/krml
    FILES_MATCHING PATTERN "*.h")
install(DIRECTORY karamel/krmllib/dist/minimal/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/krml
    FILES_MATCHING PATTERN "*.h")

# # Install vale headers
install(DIRECTORY vale/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vale
    FILES_MATCHING PATTERN "*.h")

# # Install config.h
install(FILES build/config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hacl)

# The CPU detection is used for testing and benchmarking
if(ENABLE_TESTS OR ENABLE_BENCHMARKS)
    # CPU feature detection for tests
    add_library(hacl_cpu_features OBJECT ${PROJECT_SOURCE_DIR}/cpu-features/src/cpu-features.c)
    target_include_directories(hacl_cpu_features PUBLIC ${PROJECT_SOURCE_DIR}/cpu-features/include)
endif(ENABLE_TESTS OR ENABLE_BENCHMARKS)

# Add ecckiila for benchmarks
if(ENABLE_BENCHMARKS)
    include(${PROJECT_SOURCE_DIR}/third-party/ecckiila/config.cmake)
    add_library(ecckiila OBJECT ${SOURCES_ecckiila})
endif(ENABLE_BENCHMARKS)

# Add blake2 for benchmarks
if(ENABLE_BENCHMARKS)
    include(${PROJECT_SOURCE_DIR}/third-party/blake2/config.cmake)
    add_library(blake2 OBJECT ${SOURCES_blake2_ref})
    target_include_directories(blake2 PUBLIC ${PROJECT_SOURCE_DIR}/third-party/blake2/ref)
endif(ENABLE_BENCHMARKS)

# Add digestif for benchmarks
if(ENABLE_BENCHMARKS)
    include(${PROJECT_SOURCE_DIR}/third-party/digestif/config.cmake)
    add_library(digestif OBJECT ${SOURCES_digestif})
    target_include_directories(digestif PUBLIC ${PROJECT_SOURCE_DIR}/third-party/digestif)
endif(ENABLE_BENCHMARKS)


# Testing
# It's only one binary. Everything else is done with gtest arguments.
if(ENABLE_TESTS)
    # Get gtests
    include(FetchContent)
    FetchContent_Declare(googletest
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
    )

    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    # Get nlohmann json
    FetchContent_Declare(json
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        URL https://github.com/nlohmann/json/archive/refs/tags/v3.10.3.zip
    )
    FetchContent_MakeAvailable(json)

    foreach(TEST_FILE IN LISTS TEST_SOURCES)
        get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
        add_executable(${TEST_NAME}
            ${TEST_FILE}
        )

        # Coverage
        if(ENABLE_COVERAGE)
            target_compile_options(${TEST_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
            target_link_options(${TEST_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
        endif()

        if(MSVC)
            # MSVC needs a modern C++ for designated initializers.
            target_compile_options(${TEST_NAME} PRIVATE /std:c++20)
        endif(MSVC)

        add_dependencies(${TEST_NAME} hacl libcrux_static hacl_cpu_features)
        target_link_libraries(${TEST_NAME} PRIVATE
            gtest_main
            hacl_static
            libcrux_static
            hacl_cpu_features
            nlohmann_json::nlohmann_json
        )
        target_include_directories(${TEST_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/cpu-features/include)

        if(EXISTS ${PROJECT_SOURCE_DIR}/tests/${TEST_NAME})
            # Copy test input files. They must be in a directory with the same
            # name as the test and get copied to the build directory.
            add_custom_command(TARGET ${TEST_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${PROJECT_SOURCE_DIR}/tests/${TEST_NAME} $<TARGET_FILE_DIR:${TEST_NAME}>)
        endif()
    endforeach()

    if(BUILD_LIBCRUX)
        foreach(TEST_FILE IN LISTS LIBCRUX_TEST_SOURCES)
            get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
            add_executable(${TEST_NAME}
                ${TEST_FILE}
            )

            # Coverage
            if(ENABLE_COVERAGE)
                target_compile_options(${TEST_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
                target_link_options(${TEST_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
            endif()

            if(MSVC)
                # MSVC needs a modern C++ for designated initializers.
                target_compile_options(${TEST_NAME} PRIVATE /std:c++20)
            endif(MSVC)

            add_dependencies(${TEST_NAME} hacl libcrux_static hacl_cpu_features)
            target_link_libraries(${TEST_NAME} PRIVATE
                gtest_main
                hacl_cpu_features
                nlohmann_json::nlohmann_json
                libcrux_static
                hacl_static
            )

            if(EXISTS ${PROJECT_SOURCE_DIR}/tests/${TEST_NAME})
                # Copy test input files. They must be in a directory with the same
                # name as the test and get copied to the build directory.
                add_custom_command(TARGET ${TEST_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_directory
                    ${PROJECT_SOURCE_DIR}/tests/${TEST_NAME} $<TARGET_FILE_DIR:${TEST_NAME}>)
            endif()
        endforeach()
    endif()
endif()

# Benchmarks
if(ENABLE_BENCHMARKS)
    message(STATUS "Building benchmarks")
    # find_package(benchmark REQUIRED)
    include(FetchContent)
    set(CMAKE_C_STANDARD 11)

    # We need gtest as well
    FetchContent_Declare(googletest
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
    )

    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    FetchContent_Populate(benchmark
        GIT_REPOSITORY  https://github.com/google/benchmark.git
        # The latest release 1.7.1 is broken due to https://github.com/google/benchmark/pull/1517
        # But also: need the fix for https://github.com/google/benchmark/pull/1669
        GIT_TAG         bc946b919cac6f25a199a526da571638cfde109f
    )
    add_subdirectory(${benchmark_SOURCE_DIR} ${benchmark_BINARY_DIR})

    foreach(BENCH_FILE IN LISTS BENCHMARK_SOURCES)
        get_filename_component(BENCH_NAME ${BENCH_FILE} NAME_WE)
        set(BENCH_NAME ${BENCH_NAME}_benchmark)
        add_executable(${BENCH_NAME}
            ${BENCH_FILE}
        )

        if(ENABLE_OPENSSL_BENCHMARKS)
            if(DEFINED ENV{OPENSSL_HOME})
                target_include_directories(${BENCH_NAME} PUBLIC $ENV{OPENSSL_HOME}/include/)
                target_link_directories(${BENCH_NAME} PRIVATE $ENV{OPENSSL_HOME}/lib)
            endif()
            target_link_libraries(${BENCH_NAME} PRIVATE crypto)
        else()
            target_compile_definitions(${BENCH_NAME} PUBLIC NO_OPENSSL)
        endif(ENABLE_OPENSSL_BENCHMARKS)

        if(ENABLE_LIBTOMCRYPT_BENCHMARKS)
            if(DEFINED ENV{LIBTOMCRYPT_HOME})
                target_include_directories(${BENCH_NAME} PUBLIC $ENV{LIBTOMCRYPT_HOME}/include/)
                target_link_directories(${BENCH_NAME} PRIVATE $ENV{LIBTOMCRYPT_HOME}/lib)
            endif()
            target_link_libraries(${BENCH_NAME} PRIVATE tomcrypt)
            target_compile_definitions(${BENCH_NAME} PUBLIC LIBTOMCRYPT)
        endif(ENABLE_LIBTOMCRYPT_BENCHMARKS)

        # Use modern C++
        if(NOT MSVC)
            target_compile_options(${BENCH_NAME} PRIVATE -std=c++17)
        else()
            # MSVC needs a modern C++ for designated initializers.
            target_compile_options(${BENCH_NAME} PRIVATE /std:c++20)
        endif(NOT MSVC)

        add_dependencies(${BENCH_NAME} hacl libcrux_static hacl_cpu_features)
        target_link_libraries(${BENCH_NAME} PRIVATE
            hacl_static
            libcrux_static
            ecckiila
            blake2
            digestif
            hacl_cpu_features
            benchmark::benchmark
        )
    endforeach()

    if(BUILD_LIBCRUX)
        foreach(BENCH_FILE IN LISTS LIBCRUX_BENCHMARK_SOURCES)
            get_filename_component(BENCH_NAME ${BENCH_FILE} NAME_WE)
            set(BENCH_NAME ${BENCH_NAME}_benchmark)
            add_executable(${BENCH_NAME}
                ${BENCH_FILE}
            )

            # Use modern C++
            if(NOT MSVC)
                target_compile_options(${BENCH_NAME} PRIVATE -std=c++17)
            else()
                # MSVC needs a modern C++ for designated initializers.
                target_compile_options(${BENCH_NAME} PRIVATE /std:c++20)
            endif(NOT MSVC)

            target_compile_definitions(${BENCH_NAME} PUBLIC NO_OPENSSL)

            add_dependencies(${BENCH_NAME} hacl libcrux_static hacl_cpu_features)
            target_link_libraries(${BENCH_NAME} PRIVATE
                hacl_cpu_features
                benchmark::benchmark
                libcrux_static
                hacl_static
            )
        endforeach()
    endif()
endif(ENABLE_BENCHMARKS)
