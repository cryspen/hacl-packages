
# Options for features.
# They all default to off and have to be explicitely enabled.
option(DISABLE_VEC128 "Disable code requiring vec128 hardware support.")
option(DISABLE_VEC256 "Disable code requiring vec256 hardware support.")
option(DISABLE_VALE "Disable vale code.")
option(DISABLE_INLINE_ASM "Disable inline assembly code.")
option(DISABLE_INTRINSICS "Disable intrinsics.")
if(DISABLE_VEC128)
    set(TOOLCHAIN_CAN_COMPILE_VEC128 OFF)
    message(STATUS "vec128 support: ${TOOLCHAIN_CAN_COMPILE_VEC128} (MANUALLY DISABLED)")
endif()
if(DISABLE_VEC256)
    set(TOOLCHAIN_CAN_COMPILE_VEC256 OFF)
    message(STATUS "vec256 support: ${TOOLCHAIN_CAN_COMPILE_VEC256} (MANUALLY DISABLED)")
endif()
if(DISABLE_VALE)
    set(TOOLCHAIN_CAN_COMPILE_VALE OFF)
    message(STATUS "vale support: ${TOOLCHAIN_CAN_COMPILE_VALE} (MANUALLY DISABLED)")
endif()
if(DISABLE_INLINE_ASM)
    set(TOOLCHAIN_CAN_COMPILE_INLINE_ASM OFF)
endif()
if(DISABLE_INTRINSICS)
    set(TOOLCHAIN_CAN_COMPILE_INTRINSICS OFF)
endif()

# Enable tests.
# By default tests aren't built
option(ENABLE_TESTS "Enable HACL tests.")

# Sannitaizers
option(ENABLE_ASAN "Enable address sanitizers.")
option(ENABLE_UBSAN "Enable undefined behaviour sanitizers.")
