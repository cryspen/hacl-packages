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

By default the top-level `src` and `include` directories are used.
When compiling for `c89` or specific `msvc` versions, the respective `src` and `include` subdirectories are used.

```
- src/
- src/c89
- src/msvc
- include/
- include/c89
- include/msvc
- tests/remote
```

Vale is considered an external dependency and is pulled into a separate `vale` directory.

```
- vale/src
- vale/include
```

The handwritten C++ code for tests is stored in

```
/tests
```

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

## Platform Support

HACL\* is supported based on the following tiers.

### Tier 1

Tier 1 targets are guaranteed to work. These targets have automated testing to
ensure that changes do not break them.

- x86_64 Linux (x86_64-unknown-linux-gnu)
- x86 Linux (i686-unknown-linux-gnu)
- x86_64 macOS (x86_64-apple-darwin)
- x86_64 Windows (x86_64-pc-windows-msvc)
- x86 Windows (i686-pc-windows-msvc)

### Tier 2

Tier 2 targets are guaranteed to build.
These targets have automated builds to ensure that changes do not break the
builds. However, not all of them are always tested.

- arm64 macOS (aarch64-apple-darwin)
- arm64 Linux (aarch64-unknown-linux-gnu)
- arm64 Android (aarch64-linux-android)
- arm64 iOS (aarch64-apple-ios)

### Tier 3

Tier 3 targets are supported by the code but there are no automated checks and
they might break in new versions.

- ARMv7 Android (aarch64arm-linux-androideabi)
- arm64 iOS Simulator (aarch64-apple-ios-sim)
- x86_64 iOS (x86_64-apple-ios)
- PowerPC
- IBM Z15
- FreeBSD / x64

## Algorithms

The following tables gives an overview over the algorithms supported by HACL\*.

| Family               | Algorithm         | Support                                 |
| -------------------- | ----------------- | --------------------------------------- |
| AEAD                 | AES-GCM 128       | AES-NI & CLMUL                          |
| AEAD                 | AES-GCM 256       | AES-NI & CLMUL                          |
| AEAD                 | Chacha20-Poly1305 | Portable \| vec128 \| vec256            |
| ECDH                 | Curve25519        | Portable \| BMI2 & ADX                  |
| ECDH                 | P-256             | Portable                                |
| Signature            | Ed25519           | Portable                                |
| Signature            | P-256             | Portable                                |
| Hash                 | SHA2-224          | Portable \| SHAEXT                      |
| Hash                 | SHA2-256          | Portable \| SHAEXT                      |
| Hash                 | SHA2-384          | Portable                                |
| Hash                 | SHA2-512          | Portable                                |
| Hash                 | SHA3              | Portable                                |
| Hash                 | Blake2            | Portable \| vec128 \| vec256            |
| Key Derivation       | HKDF              | Portable (depends on hash)              |
| Symmetric Encryption | Chacha20          | Portable \| vec128 \| vec256            |
| Symmetric Encryption | AES 128           | AES-NI & CLMUL                          |
| Symmetric Encryption | AES 256           | AES-NI & CLMUL                          |
| MAC                  | HMAC              | Portable (depends on hash)              |
| MAC                  | Poly1305          | Portable \| vec128 \| vec256 \| x64 ASM |

## Testing

Testing is done with [gtest] and requires a C++11 compiler.

### Dependencies

Tests require the [nlohmann_json] package to read json test files.
CMake takes care of pulling and building the package.

## Code Style

Handwritten C and CPP code is formatted with the Mozilla clang-format style.

[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
[mach.py]: ./mach.py
[gtest]: https://google.github.io/googletest/
[nlohmann_json]: https://github.com/nlohmann/json
[status]: https://img.shields.io/badge/status-experimental-red.svg?style=for-the-badge
