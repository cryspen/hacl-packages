# OCaml

There are two different ways of building the OCaml bindings.

## Standalone (Packaging)

For packaging the hacl-star opam package the bindings can be built standalone.

```bash
./opam.sh
cd opam
```

First we need to get the HACL C code, build it, and put it where the Makefile
expects the result.
The `opam.sh` script puts everything in the right place within the `opam` directory.
In the directory we can now build/install the opam package(s) `hacl-star` (and `hacl-star-raw`).

```bash
opam install . --verbose --with-test --yes
```

Documentation can be built with

```bash
dune build @doc --only-packages=hacl-star
```

## Mach (Dev Mode)

> ⚠️ The dev mode is not working right now

When working on the library `mach` offers a convenient way of building the C
library and the ocaml bindings through `mach` using the `-l|--language` argument.

```
./mach build -l ocaml
```

This build the C library, copies the result into the `ocaml` directory, and then
builds the OCaml bindings on top.
Tests can be called through mach as well `./mach test -l ocaml`.
