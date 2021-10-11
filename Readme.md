# HACL

![][status]

This is an attempt to get a build system for the HACL C library.
This is the "high-level" C library that will be generated and maintained.

## Structure

The main source and include directories are populated with upstream generated
C code and must not be changed manually.
`./mach.py update` can be used to update the code from upstream.
This also pulls in upstream tests.
(Note however that these tests are very limited.)

```
- src/
- include/
- tests/
```

Vale is considered an external dependency and is pulled into a separate `vale` directory.

```
- vale/src
- vale/include
```

The handwritten C code for tests is stored in `testing`.

## Build

HACL uses [cmake] to configure the build and [ninja] to build.

Quick start: `./mach.py build --test`

### mach

To make building easier the [mach.py] can be used to trigger cmake and ninja.

```
usage: mach.py [-h] {update,test,snapshot,build,clean} ...

positional arguments:
  {update,test,snapshot,build,clean}

optional arguments:
  -h, --help            show this help message and exit
```

#### Build

```
usage: mach.py build [-h] [-c] [-t] [-r] [-a ALGORITHMS] [-p TARGET] [-d DISABLE] [-v]

Main entry point for building HACL

    For convenience it is possible to run tests right after building using -t.

    Supported cross compilation targets:
        - x64-macos

    Features that can be disabled:
        - vec128 (avx/neon)
        - vec256 (avx2)
        - vale (x64 assembly)


optional arguments:
  -h, --help            show this help message and exit
  -c, --clean           Clean before building.
  -t, --test            Run tests after building.
  -r, --release         Build in release mode.
  -a ALGORITHMS, --algorithms ALGORITHMS
                        A list of algorithms to enable. Defaults to all.
  -p TARGET, --target TARGET
                        Define compile target for cross compilation.
  -d DISABLE, --disable DISABLE
                        Disable hardware features even if available.
  -v, --verbose         Make builds verbose.
```

## Testing

Testing is done with [gtest] and requires a C++11 compiler.

### Dependencies
Tests require the [nlohmann_json] package to read json test files.

## Code Style
Handwritten C and CPP code is formatted with the Mozilla clang-format style.

[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
[mach.py]: ./mach.py
[gtest]: https://google.github.io/googletest/
[nlohmann_json]: https://github.com/nlohmann/json
[status]: https://img.shields.io/badge/status-experimental-red.svg?style=for-the-badge
