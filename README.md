# The Cryspen HACL Packages

This repository contains ready-to-use crypto packages developed by [Cryspen] on top of [HACL*].
In particular, it contains a portable C crypto library that selects optimized implementations for each platform,
as well as Rust, OCaml, and JavaScript bindings for this library.

Currently, we are in the process of adding more usable APIs, [providing extensive documentation](https://cryspen.com/hacl-packages/), and further optimizing the algorithms.

## What is HACL\* and why should you use HACL Packages?

[HACL*] is a collection of high-assurance cryptographic algorithms developed as part of [Project Everest].
It includes source code written in [F*], generated C code, verified assembly code from the [Vale] project, and an agile multiplexed cryptographic provider called [EverCrypt].
As such, the full HACL\* repository contains many software artifacts and a complicated build system that can be intimidating to a crypto developer who simply wishes to use verified crypto.

## Quickstart

### Install build dependencies

We need the following dependencies ...

- [cmake] (3.17 or newer)
- [ninja] (1.10 or newer)
- [python] (3.6 or newer)
- [clang] (7 or newer) or [gcc] (7 or newer)

Depending on your system you can install them as follows (click to expand) ...

<details>
  <summary><b>Arch Linux</b></summary>

```sh
$ sudo pacman -S cmake ninja python

# Either of ...
$ sudo pacman -S clang
$ sudo pacman -S gcc
```
</details>

<details>
  <summary><b>Fedora</b></summary>
  
```sh
$ sudo dnf install cmake ninja-build python3

# Either of ...
$ sudo dnf install clang
$ sudo dnf install gcc
```
</details>

<details>
  <summary><b>Ubuntu</b></summary>
  
```sh
$ sudo apt install cmake ninja-build python3

# Either of ...
$ sudo apt install clang
$ sudo apt install gcc
```
</details>

<details>
  <summary><b>macOS</b></summary>

```sh
$ brew install cmake ninja python

# Either of ...
$ brew install llvm
$ brew install gcc
```
</details>

## Build (and test) HACL Packages

You can run ...

```sh
$ ./mach build --test
```

... to build HACL Packages and run the tests. All actions are driven by [mach]. See `./mach --help` for details.

## Platform support

The HACL Packages are supported based on the following tiers.

### Tier 1

Tier 1 targets are guaranteed to work. These targets have automated testing to
ensure that changes do not break them.

- [x] x86_64 Linux (x86_64-unknown-linux-gnu)
- [x] x86 Linux (i686-unknown-linux-gnu)
- [x] x86_64 macOS (x86_64-apple-darwin)
- [x] x86_64 Windows
  - [x] x86_64-pc-windows-msvc
  - [x] x86_64-pc-windows-clang
- [x] x86 Windows (i686-pc-windows-msvc)

### Tier 2

Tier 2 targets are guaranteed to build.
These targets have automated builds to ensure that changes do not break the
builds. However, not all of them are always tested.

- [x] arm64 macOS (aarch64-apple-darwin)
- [x] arm64 Linux (aarch64-unknown-linux-gnu)
- [x] arm64 Android (aarch64-linux-android)
- [x] arm64 iOS (aarch64-apple-ios)
- [x] s390x z14 Linux (s390x-unknown-linux-gnu)

### Tier 3

Tier 3 targets are supported by the code but there are no automated checks and
there is no guarantee that they work.

- ARMv7 Android (aarch64arm-linux-androideabi)
- arm64 iOS Simulator (aarch64-apple-ios-sim)
- x86_64 iOS (x86_64-apple-ios)
- PowerPC
- FreeBSD / x64

## Compiler support

<!-- When using the `c89` edition of HACL GCC 4.8 and up are supported.
In any other case a modern C compiler is expected. -->

A modern C compiler is expected.

## Algorithms

The following tables gives an overview over the algorithms supported by the HACL
packages.

| Family               | Algorithm         | Support                                 |
| -------------------- | ----------------- | --------------------------------------- |
| AEAD                 | AES-GCM 128       | AES-NI & CLMUL (x86 only)               |
| AEAD                 | AES-GCM 256       | AES-NI & CLMUL (x86 only)               |
| AEAD                 | Chacha20-Poly1305 | Portable \| vec128 \| vec256            |
| ECDH                 | Curve25519        | Portable \| BMI2 & ADX                  |
| ECDH                 | P-256             | Portable                                |
| Signature            | Ed25519           | Portable                                |
| Signature            | ECDSA P-256r1     | Portable                                |
| Signature            | ECDSA P-256k1     | Portable                                |
| Signature            | RSA-PSS           | Portable                                |
| Hash                 | SHA2-224          | Portable \| SHAEXT                      |
| Hash                 | SHA2-256          | Portable \| SHAEXT                      |
| Hash                 | SHA2-384          | Portable                                |
| Hash                 | SHA2-512          | Portable                                |
| Hash                 | SHA3              | Portable                                |
| Hash                 | Blake2            | Portable \| vec128 \| vec256            |
| Key Derivation       | HKDF              | Portable (depends on hash)              |
| Symmetric Encryption | Chacha20          | Portable \| vec128 \| vec256            |
| Symmetric Encryption | AES 128           | AES-NI & CLMUL (x86 only)               |
| Symmetric Encryption | AES 256           | AES-NI & CLMUL (x86 only)               |
| MAC                  | HMAC              | Portable (depends on hash)              |
| MAC                  | Poly1305          | Portable \| vec128 \| vec256 \| x64 ASM |

## Testing

Testing is done with [gtest] and requires a C++11 compiler (or C++20 MSVC).

### Measure Test Coverage

Test coverage in HACL Packages can be measured with ...

```sh
./mach build --tests --coverage
./mach test --coverage
./tools/coverage.sh
```

Note that only clang is supported as a compiler and you may get an error ...

```
cc: error: unrecognized command-line option ‘-fprofile-instr-generate’; did you mean ‘-fprofile-generate’?
```

... when your default compiler is not clang.
In this case, try to set the `CC` and `CXX` environment variables accordingly ...

```sh
export CC=clang
export CXX=clang++
```

Furthermore, additional tools are required to measure (and view) test coverage.

Make sure you have `lcov` and `genhtml`.

For Ubuntu these can be installed via ...

```sh
$ sudo apt install lcov
```

When everything went well you should be able to view the coverage reports with, e.g., ...

```sh
firefox build/Debug/coverage/full/html/index.html
```

### Dependencies

Tests require the [nlohmann_json] package to read json test files.
CMake takes care of pulling and building the package.

## License

HACL packages are licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

[//]: # "links"
[cryspen]: https://www.cryspen.com/
[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
[clang]: https://clang.llvm.org/
[gcc]: https://gcc.gnu.org/
[mach]: ./mach
[gtest]: https://google.github.io/googletest/
[nlohmann_json]: https://github.com/nlohmann/json
[hacl*]: https://hacl-star.github.io
[f*]: https://fstar-lang.org
[vale]: https://hacl-star.github.io/HaclValeEverCrypt.html
[evercrypt]: https://hacl-star.github.io/HaclValeEverCrypt.html
[status]: https://img.shields.io/badge/status-beta-orange.svg?style=for-the-badge
[project everest]: https://project-everest.github.io/
[python]: https://www.python.org/
