# OCaml

There are two different ways of building the OCaml bindings.

## Mach (Dev Mode)

When working on the library `mach` offers a convenient way of building the C
library and the ocaml bindings through `mach` using the `-l|--language` argument.

```
./mach build -l ocaml
```

This build the C library, copies the result into the `ocaml` directory, and then
builds the OCaml bindings on top.
Tests can be called through mach as well `./mach test -l ocaml`.

## Standalone (Packaging)

For packaging the hacl-star opam package the bindings can be built standalone.
In this case the local copy of the HACL C library is ignored.
Instead a fresh copy is pulled from the git repository and built locally within
the `ocaml` directory.
The following command run in the `ocaml` directory will build a standalone
version of the package.

```
./setup.py
export HACL_MAKE_CONFIG=hacl-packages/config/cached-config.txt
make ocamlevercrypt.cmxa
make -j
```

First we need to get the HACL C code, build it, and put it where the Makefile
expects the result.
This is what the `setup.py` script does.
Because the OCaml build requires information about the platform features we
export `HACL_MAKE_CONFIG` to point to the CMake generated information.
Then we can build the bindings with make.
