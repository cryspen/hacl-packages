# Toolchain file compiling for s390x

set(triple s390x-linux-gnu)
set(arch s390x)
set(HACL_TARGET_OS linux)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_C_COMPILER_TARGET ${triple})
set(CMAKE_CXX_COMPILER_TARGET ${triple})
# This isn't working unfortunately. It's being set in CMakeLists.txt again
set(CMAKE_SYSTEM_PROCESSOR s390x)
