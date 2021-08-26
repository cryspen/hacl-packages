# Evercrypt C

![][Status]

This is an attempt to get a build system for the Evercrypt C library.
This is the "high-level" C library that will be generated and maintained.

## Build
Evercrypt uses [cmake] to configure the build and [ninja] to build.
To make building easier the [mach.sh] can be used to trigger cmake and ninja.

```
Usage: mach.sh [-h] [-c] [-cc] [--full] [--test] [--release]

Helper script to build and test evercrypt with CMake, ctest, and ninja.

Options:

    -h        display this help and exit
    -c        clean before build
    -cc       only clean
    --full    enable all available features
    --test    run tests through ctest; build before if necessary
    --release release builds and tests

```

## Testing
Testing is done through [ctest] for convenience.
But all tests can be run through their respective binaries if needed.

[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
[mach.sh]: ./mach.sh
[ctest]: https://cmake.org/cmake/help/latest/manual/ctest.1.html
[Status]: https://img.shields.io/badge/status-experimental-red.svg?style=for-the-badge
