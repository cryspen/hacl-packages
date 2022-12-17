# Build Process

The HACL C library is built with [CMake] and [ninja] and uses a Python driver
script called `mach`.
Due to the modular nature of the library the build is more complex than for
many other libraries.

## Selecting Algorithms

The algorithms compiled into the library can be selected using the `-a|--algorithm`
argument on `mach`.
By default all algorithms are selected.
The files used in the build are selected by running a dependency analysis on the
requested algorithm files (see `configure.py`).
The resulting configuration is written into `build/config.cmake`, which is used
as input into the main build process.
This process is part of the `mach` script.

## Platform Detection

Depending on the used toolchain a different set of algorithms can be used.
In order to define the feature set available in the toolchain CMake runs a set
of tests.
Note that the toolchain feature must not be the same as the platform feature
set the build is running on (due to cross compilation or extended features in the
toolchain compared to the actual hardware).
The library has runtime feature detection to ensure that hardware features are
only used when they are actually available.

## Release Builds

By default the builds use the debug mode.
For release builds

```
./mach build --release
```

is used.

[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
