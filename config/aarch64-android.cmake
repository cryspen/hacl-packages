# Toolchain file compiling for aarch64 Android

set(triple aarch64-linux-android)
set(arch aarch64)

# For some reason we have to set the system name here in order to make the
# CMAKE_SYSTEM_PROCESSOR being picked up correctly.
set(CMAKE_SYSTEM_NAME Android)
# We don't set the cmake version here as Android comes with an ancient cmake.
# set(CMAKE_SYSTEM_VERSION "${CMAKE_HOST_SYSTEM_VERSION}")
set(CMAKE_SYSTEM_PROCESSOR ${arch})
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_NDK "${ANDROID_NDK_PATH}")
set(HACL_TARGET_OS android)
