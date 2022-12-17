# Platforms

The HACL Packages are supported based on the following tiers.

For a detailed description of the different supported architecture see the [next section](./architectures.md).

### Tier 1

Tier 1 targets are guaranteed to work. These targets have automated testing to
ensure that changes do not break them.

- x86_64 Linux (x86_64-unknown-linux-gnu)
- x86 Linux (i686-unknown-linux-gnu)
- x86_64 macOS (x86_64-apple-darwin)
- x86_64 Windows
  - x86_64-pc-windows-msvc
  - x86_64-pc-windows-clang
- x86 Windows (i686-pc-windows-msvc)

### Tier 2

Tier 2 targets are guaranteed to build.
These targets have automated builds to ensure that changes do not break the
builds. However, not all of them are always tested.

- arm64 macOS (aarch64-apple-darwin)
- arm64 Linux (aarch64-unknown-linux-gnu)
- arm64 Android (aarch64-linux-android)
- arm64 iOS (aarch64-apple-ios)
- s390x z14 Linux (s390x-unknown-linux-gnu)

### Tier 3

Tier 3 targets are supported by the code but there are no automated checks and
there is no guarantee that they work.

- ARMv7 Android (aarch64arm-linux-androideabi)
- arm64 iOS Simulator (aarch64-apple-ios-sim)
- x86_64 iOS (x86_64-apple-ios)
- PowerPC
- IBM Z15
- FreeBSD / x64
