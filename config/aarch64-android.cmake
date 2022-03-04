# Toolchain file compiling for aarch64 Android

set(triple aarch64-linux-android)
set(arch aarch64)
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_NDK /Users/franziskus/Library/Android/sdk/ndk/23.1.7779620)
set(HACL_TARGET_OS android)
# set(CMAKE_C_COMPILER clang)
# set(CMAKE_C_COMPILER_TARGET ${triple})
# set(CMAKE_CXX_COMPILER clang++)
# set(CMAKE_CXX_COMPILER_TARGET ${triple})
# This isn't working unfortunately. It's being set in CMakeLists.txt again
set(CMAKE_SYSTEM_PROCESSOR ${arch})
set(CMAKE_OSX_ARCHITECTURES ${arch})
