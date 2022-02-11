# HACL

![][status]

The High Assurance Crypto Library (HACL) is a C library with Rust, OCaml, and
JavaScript bindings based on [HACL*], [Vale], and [Evercrypt].

## Build

HACL uses [cmake] to configure the build and [ninja] to build.

Quick start: `./mach build --test`

## mach

All actions on HACL are driven by [mach].
See `./mach --help` for details.

## Platform Support

HACL is supported based on the following tiers.

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
- s390x Linux (s390x-unknown-linux-gnu)

### Tier 3

Tier 3 targets are supported by the code but there are no automated checks and
there is no guarantee that they work.

- ARMv7 Android (aarch64arm-linux-androideabi)
- arm64 iOS Simulator (aarch64-apple-ios-sim)
- x86_64 iOS (x86_64-apple-ios)
- PowerPC
- IBM Z15
- FreeBSD / x64

## Compiler support
When using the `c89` edition of HACL GCC starting from 4.8 is supported.

TODO: define clang and MSVC version support

## Algorithms

The following tables gives an overview over the algorithms supported by HACL\*.

| Family               | Algorithm         | Support                                 |
| -------------------- | ----------------- | --------------------------------------- |
| AEAD                 | AES-GCM 128       | AES-NI & CLMUL (x86 only)               |
| AEAD                 | AES-GCM 256       | AES-NI & CLMUL (x86 only)               |
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
| Symmetric Encryption | AES 128           | AES-NI & CLMUL (x86 only)               |
| Symmetric Encryption | AES 256           | AES-NI & CLMUL (x86 only)               |
| MAC                  | HMAC              | Portable (depends on hash)              |
| MAC                  | Poly1305          | Portable \| vec128 \| vec256 \| x64 ASM |

## Testing

Testing is done with [gtest] and requires a C++11 compiler.

### Dependencies

Tests require the [nlohmann_json] package to read json test files.
CMake takes care of pulling and building the package.

## Code Style

Handwritten C and CPP code is formatted with the Mozilla clang-format style.

[//]: # "links"
[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
[mach]: ./mach
[gtest]: https://google.github.io/googletest/
[nlohmann_json]: https://github.com/nlohmann/json
[status]: https://img.shields.io/badge/status-alpha-red.svg?style=for-the-badge
[hacl*]: https://hacl-star.github.io
[vale]: https://hacl-star.github.io/HaclValeEverCrypt.html
[evercrypt]: https://hacl-star.github.io/HaclValeEverCrypt.html
