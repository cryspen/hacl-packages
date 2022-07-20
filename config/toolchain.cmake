# Test the toolchain to get supported CPU features

INCLUDE(CheckCCompilerFlag)
set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)

## Check for gcc compiler bug 81300
if(NOT DEFINED BUG_81300)
    try_compile(BUG_81300
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/bug81300.c
                        # TODO: get the include paths from global variables
                        #       We should probably get rid of the march=native!
                        COMPILE_DEFINITIONS "-DCOMPILE_INTRINSICS \
                                             -O3"
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
if(${INT128_SUPPORT})
    set(HACL_CAN_COMPILE_UINT128 1)
endif()

## Check for explicit_bzero support
if(NOT DEFINED EXPLICIT_BZERO_SUPPORT)
    try_compile(EXPLICIT_BZERO_SUPPORT
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/explicit_bzero.c
                )
endif()
message(STATUS "explicit_bzero support: ${EXPLICIT_BZERO_SUPPORT}")

## Check for vec128 support
if(NOT DEFINED TOOLCHAIN_CAN_COMPILE_VEC128)
    set(CPU_FLAGS "")
    # TODO: read these flag from a common definition
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
        set(CPU_FLAGS "${CPU_FLAGS} -msse2 -msse3 -msse4.1 -msse4.2")
    endif()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "s390x")
        set(CPU_FLAGS "${CPU_FLAGS} -mzarch -mvx -mzvector -march=z14")
    endif()
    try_compile(TOOLCHAIN_CAN_COMPILE_VEC128
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/vec128.c
                        # TODO: get the include paths from global variables
                        #       When do we need -march=armv8-a+simd or something else here?
                        COMPILE_DEFINITIONS "-DHACL_CAN_COMPILE_VEC128 \
                                             -I${PROJECT_SOURCE_DIR}/include \
                                             -I${PROJECT_SOURCE_DIR}/karamel/include \
                                             -I${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal \
                                             ${CPU_FLAGS}"
                )
endif()
message(STATUS "vec128 support: ${TOOLCHAIN_CAN_COMPILE_VEC128}")

## Check for vec256 support
if(NOT DEFINED TOOLCHAIN_CAN_COMPILE_VEC256)
    set(CPU_FLAGS "")
    # TODO: read these flag from a common definition
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i586|i686|i86pc|ia32|x86_64|amd64|AMD64")
        set(CPU_FLAGS "${CPU_FLAGS} -mavx2 -mavx")
    endif()
    try_compile(TOOLCHAIN_CAN_COMPILE_VEC256
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/vec256.c
                        # TODO: get the include paths from global variables
                        #       When do we need -march=armv8-a+simd or something else here?
                        COMPILE_DEFINITIONS "-DHACL_CAN_COMPILE_VEC256  \
                                             -I${PROJECT_SOURCE_DIR}/include \
                                             -I${PROJECT_SOURCE_DIR}/karamel/include \
                                             -I${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal \
                                             ${CPU_FLAGS}"
                )
endif()
message(STATUS "vec256 support: ${TOOLCHAIN_CAN_COMPILE_VEC256}")

## Check for vale support
if(NOT DEFINED TOOLCHAIN_CAN_COMPILE_VALE)
    # Always enable for x64
    set(TOOLCHAIN_CAN_COMPILE_VALE FALSE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        set(TOOLCHAIN_CAN_COMPILE_VALE TRUE)
    endif()
endif()

# Check for inline assembly support
if(NOT DEFINED TOOLCHAIN_CAN_COMPILE_INLINE_ASM)
    set(TOOLCHAIN_CAN_COMPILE_INLINE_ASM OFF)
    # Only available on x64
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        execute_process(COMMAND
            ${PROJECT_SOURCE_DIR}/config/osx_c.sh ${CMAKE_C_COMPILER}
            RESULT_VARIABLE BAD_CC
        )
        if(${BAD_CC} EQUAL 1)
            set(TOOLCHAIN_CAN_COMPILE_INLINE_ASM TRUE)
        endif()
    endif()
endif()

# Check for intrinsics support
if(NOT DEFINED TOOLCHAIN_CAN_COMPILE_INTRINSICS)
    set(TOOLCHAIN_CAN_COMPILE_INTRINSICS OFF)
    # x86_64
    # x86 (i386|i586|i686|i86pc|ia32) has been used before but doesn't
    # actually work so it's disabled here.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        if(NOT BUG_81300)
            set(TOOLCHAIN_CAN_COMPILE_INTRINSICS TRUE)
        endif()
    endif()
endif()

# Set OS consistently for compiling, independent of cross-compilation
# Note that HACL_TARGET_OS is set by the cross-compilation tool chain when using
# one.
if(NOT HACL_TARGET_OS)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        set(HACL_TARGET_OS linux)
    endif()
    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set(HACL_TARGET_OS osx)
    endif()
    if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        if(${MINGW})
            set(HACL_TARGET_OS mingw)
        else()
            set(HACL_TARGET_OS msvc)
        endif()
    endif()
endif()
