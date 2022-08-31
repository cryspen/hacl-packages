#! /bin/sh

set -e

rm -rf opam

mkdir -p opam/hacl-star-raw/build
cp -r config opam/hacl-star-raw
mv opam/hacl-star-raw/config/default_config.cmake opam/hacl-star-raw/build/config.cmake
mkdir opam/hacl-star-raw/src
cp src/* opam/hacl-star-raw/src/ | true
mkdir opam/hacl-star-raw/include
cp include/* opam/hacl-star-raw/include/ | true
cp -r include/internal opam/hacl-star-raw/include/
cp -r vale opam/hacl-star-raw
cp -r karamel opam/hacl-star-raw

cp CMakeLists.txt opam/hacl-star-raw

cp -r ocaml/lib opam/hacl-star-raw
cp -r ocaml/lib_gen opam/hacl-star-raw
cp ocaml/Makefile opam/hacl-star-raw
cp ocaml/ctypes.depend opam/hacl-star-raw
cp ocaml/META opam/hacl-star-raw
cp ocaml/hacl-star-raw.opam opam

cp -r ocaml/hacl-star/* opam/
