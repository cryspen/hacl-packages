# build

```
usage: mach build [-h] [-c] [--tests] [--test] [-r] [-a ALGORITHMS] [-p TARGET] [-d DISABLE]
                  [-s SANITIZER] [--msvc] [-e EDITION] [-l LANGUAGE] [-v] [-m32]

Main entry point for building HACL

    For convenience it is possible to run tests right after building using --test.

    Supported cross compilation targets:
        - x64-macos
        - s390x

    Features that can be disabled (TBD):
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
        - ocaml (TBD)
        - wasm (TBD)

    💡  Windows builds are limited. The following arguments are not supported:
        - algorithms
        - sanitizer
        - edition
        - disable
    

optional arguments:
  -h, --help            show this help message and exit
  -c, --clean           Clean before building.
  --tests               Build tests.
  --test                Build and run tests.
  -r, --release         Build in release mode.
  -a ALGORITHMS, --algorithms ALGORITHMS
                        A list of algorithms to enable. Defaults to all.
  -p TARGET, --target TARGET
                        Define compile target for cross compilation.
  -d DISABLE, --disable DISABLE
                        Disable (hardware) features even if available.
  -s SANITIZER, --sanitizer SANITIZER
                        Enable sanitizers.
  --msvc                Use MSVC on Windows (default is clang-cl).
  -e EDITION, --edition EDITION
                        Choose a different HACL* edition.
  -l LANGUAGE, --language LANGUAGE
                        Build language bindings for the given language.
  -v, --verbose         Make builds verbose.
  -m32                  Build for 32-bit (even when on 64-bit).
```
