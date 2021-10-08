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
## Check for vec128 support
if(NOT DEFINED TOOLCHAIN_CAN_COMPILE_VEC128)
    try_compile(TOOLCHAIN_CAN_COMPILE_VEC128
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/vec128.c
                        # TODO: get the include paths from global variables
                        #       When do we need -march=armv8-a+simd or something else here?
                        COMPILE_DEFINITIONS "-DHACL_CAN_COMPILE_VEC128 \
                                             -I${PROJECT_SOURCE_DIR}/include \
                                             -I${PROJECT_SOURCE_DIR}/kremlin/include \
                                             -I${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal"
                )
endif()
message(STATUS "vec128 support: ${TOOLCHAIN_CAN_COMPILE_VEC128}")
## Check for vec256 support
if(NOT DEFINED TOOLCHAIN_CAN_COMPILE_VEC256)
    try_compile(TOOLCHAIN_CAN_COMPILE_VEC256
                        ${PROJECT_SOURCE_DIR}/config/build
                        ${PROJECT_SOURCE_DIR}/config/vec256.c
                        # TODO: get the include paths from global variables
                        #       When do we need -march=armv8-a+simd or something else here?
                        COMPILE_DEFINITIONS "-DHACL_CAN_COMPILE_VEC256 \
                                             -I${PROJECT_SOURCE_DIR}/include \
                                             -I${PROJECT_SOURCE_DIR}/kremlin/include \
                                             -I${PROJECT_SOURCE_DIR}/kremlin/kremlib/dist/minimal"
                )
endif()
message(STATUS "vec256 support: ${TOOLCHAIN_CAN_COMPILE_VEC256}")

# TODO: Check for these
set(TOOLCHAIN_CAN_COMPILE_VALE OFF) # XXX: FOR TESTING ONLY
set(TOOLCHAIN_CAN_COMPILE_INLINE_ASM OFF) # XXX: FOR TESTING ONLY
set(TOOLCHAIN_CAN_COMPILE_INTRINSICS OFF) # XXX: FOR TESTING ONLY
