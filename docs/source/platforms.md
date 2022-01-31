# Platform Support

## Tiers

### Tier 1 Targets

Tier 1 targets are guaranteed to work. These targets have automated testing to ensure that changes do not break them.

- 64-bit Linux (x86_64-unknown-linux-gnu)
- 32-bit Linux (i686-unknown-linux-gnu)
- 64-bit macOS (x86_64-apple-darwin)
- 64-bit Windows (x86_64-pc-windows-msvc)
- 32-bit Windows (i686-pc-windows-msvc)

### Tier 2 Targets

Tier 2 targets are guaranteed to build. These targets have automated builds to ensure that changes do not break the builds. However, not all of them are always tested.

- ARM64 macOS (aarch64-apple-darwin)
- ARM64 Linux (aarch64-unknown-linux-gnu)
- ARM64 Android (aarch64-linux-android)
- ARM64 iOS (aarch64-apple-ios)

### Tier 3 Targets

Tier 3 targets are supported by the code but there are no automated checks and they might break in new versions.

- ARMv7 Android (aarch64arm-linux-androideabi)
- ARM64 iOS Simulator (aarch64-apple-ios-sim)
- 64-bit iOS (x86_64-apple-ios)
- PowerPC
- IBM Z15
- FreeBSD / x64