# HACL

![][Status]

This is an attempt to get a build system for the HACL C library.
This is the "high-level" C library that will be generated and maintained.

## Build
HACL uses [cmake] to configure the build and [ninja] to build.

Quick start: `./mach.py build --test`

### mach
To make building easier the [mach.py] can be used to trigger cmake and ninja.

```
usage: mach.py [-h] {configure,build,clean} ...

positional arguments:
  {configure,build,clean}

optional arguments:
  -h, --help            show this help message and exit
```

#### Build
```
usage: mach.py build [-h] [-c] [-t] [-r] [-a ALGORITHMS]

Main entry point for building HACL For convenience it is possible to run tests right
after building using -t.

optional arguments:
  -h, --help            show this help message and exit
  -c, --clean           Clean before building.
  -t, --test            Run tests after building.
  -r, --release         Build in release mode.
  -a ALGORITHMS, --algorithms ALGORITHMS
                        A list of algorithms to enable. Defaults to all.
```

#### Configure
```
usage: mach.py configure [-h] [-f FILE] [-o OUT]

Configure sub command to configure the cmake build from config.json See `run_configure` for
details.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The config.json file to read.
  -o OUT, --out OUT     The config.cmake file to write.
```

## Testing
Testing is done through [ctest] for convenience.
But all tests can be run through their respective binaries if needed.

[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
[mach.py]: ./mach.py
[ctest]: https://cmake.org/cmake/help/latest/manual/ctest.1.html
[Status]: https://img.shields.io/badge/status-experimental-red.svg?style=for-the-badge
