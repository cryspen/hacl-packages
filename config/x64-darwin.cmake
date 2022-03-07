# Toolchain file compiling for x64 macOS

set(arch x86_64)
set(triple x86_64-apple-darwin)

# For some reason we have to set the system name here in order to make the
# CMAKE_SYSTEM_PROCESSOR being picked up correctly.
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_VERSION "${CMAKE_HOST_SYSTEM_VERSION}")
set(CMAKE_SYSTEM_PROCESSOR ${arch})
set(CMAKE_OSX_ARCHITECTURES ${arch})
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET ${triple})
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_COMPILER_TARGET ${triple})

set(HACL_TARGET_OS osx)
