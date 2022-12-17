# Repository Overview

The [hacl-packages repository] is a mono repository for all HACL packages and
bindings.
The top level holds the HACL C library that is based on the output of [HACL*].

## Source Code

The C source code lives in the `src` directory for most platforms.
<!-- The c89 edition can be found in `src/c89` and the source code for MSVC is found
in `src/msvc`. -->
The source code for MSVC can be found in `src/msvc`.

<!-- The includes are found in the corresponding `include` directories (`include`,
`include/c89`, and `include/msvc`). -->

The includes can be found in the corresponding `include` directories (`include` and `include/msvc`).

Vale is considered an external dependency and therefore lives in its own
directory `vale` --- sources in `vale/src` and headers in `vale/include`.

### Tests

Tests are found in the `tests` folder and are written in modern C++ rather than
C.

### Karamel

The [KaRaMeL] dependency is found in `karamel` and holds only headers that are
used by the HACL C source code.

### CPU Features

A tool for basic CPU feature detection can be found in `cpu-features`.
This is only used for tests and will probably be removed from this repository
in future.

## Tools

The build is driven by the `mach` script and the `CMakeLists.txt`.
They rely on the contents of the `tools` folder (general tools for managing the
repository and building in Python), as well as the `config` folder (platform
detection and build configuration helper).

### Docker

Docker tools for extracting the source code from [HACL*] are found in `docker`.

### Docs

The `docs` folder contains this book you're reading right now.

## Bindings

The language bindings are in sub folders.

### Rust

The Rust bindings can be found in the `rust` folder.
See the [Rust chapter] for more details on the build and structure.

### OCaml

The OCaml bindings can be found in the `ocaml` folder.
See the [OCaml chapter] for more details on the build and structure.

[hacl-packages repository]: https://github.com/cryspen/hacl-packages
[hacl*]: https://github.com/project-everest/hacl-star
[karamel]: https://github.com/FStarLang/karamel
[ocaml chapter]: ./rust-build.md
[rust chapter]: ./ocaml-build.md
