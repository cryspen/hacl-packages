# build

```
usage: mach build [-h] [-c] [--tests] [--test] [--benchmarks] [--benchmark] [--no-openssl]
                  [--libtomcrypt] [-r] [-a ALGORITHMS] [-p TARGET] [-d DISABLE] [-s SANITIZER]
                  [--ndk NDK] [--msvc] [-e EDITION] [-l LANGUAGE] [-v] [-m32] [--no-build]
                  [--coverage]

Main entry point for building HACL

    For convenience it is possible to run tests right after building using --test.

    Supported cross compilation targets:
        - x86_64-apple-darwin (macOS aarch64 only)
        - s390x-linux-gnu
        - aarch64-apple-ios (macOS only)
        - aarch64-apple-darwin (macOS x64 only)
        - aarch64-linux-android

    Features that can be disabled:
        - vec128 (avx/neon)
        - vec256 (avx2)
        - vale (x64 assembly)

    Supported sanitizers:
        - asan
        - ubsan

    Use an edition if you want a different build. Note that this build will
    use the MSVC version by default on Windows.
    Supported editions:
        - c89

    HACL can be built for another language than C.
    Note that bindings will always require the full C library such that the
    algorithm flag will be ignored.
        - rust
        - ocaml
        - wasm (TBD)

    ! Windows builds are limited. The following arguments are not supported:
        - algorithms
        - sanitizer
        - edition
        - disable
        - coverage
    

options:
  -h, --help            show this help message and exit
  -c, --clean           Clean before building.
  --tests               Build tests.
  --test                Build and run tests.
  --benchmarks          Build benchmarks.
  --benchmark           Build and run benchmarks.
  --no-openssl          Don't build and run OpenSSL benchmarks.
  --libtomcrypt         Build and run LibTomCrypt benchmarks.
  -r, --release         Build in release mode.
  -a ALGORITHMS, --algorithms ALGORITHMS
                        A list of algorithms to enable. Defaults to all.
  -p TARGET, --target TARGET
                        Define compile target for cross compilation.
  -d DISABLE, --disable DISABLE
                        Disable (hardware) features even if available.
  -s SANITIZER, --sanitizer SANITIZER
                        Enable sanitizers.
  --ndk NDK             Path to the Android NDK.
  --msvc                Use MSVC on Windows (default is clang-cl).
  -e EDITION, --edition EDITION
                        Choose a different HACL* edition.
  -l LANGUAGE, --language LANGUAGE
                        Build language bindings for the given language.
  -v, --verbose         Make builds verbose.
  -m32                  Build for 32-bit (even when on 64-bit).
  --no-build            Don't actually build (don't run ninja).
  --coverage            Build with coverage instrumentation.
```
