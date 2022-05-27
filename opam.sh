#! /bin/sh

set -e

rm -rf opam

mkdir opam
mkdir opam/hacl-star-raw
cp -r config opam/hacl-star-raw
mv opam/hacl-star-raw/config/default_config.cmake opam/hacl-star-raw/config/config.cmake
cp -r src opam/hacl-star-raw
cp -r vale opam/hacl-star-raw
cp -r karamel opam/hacl-star-raw
cp -r include opam/hacl-star-raw

cp CMakeLists.txt opam/hacl-star-raw

cp -r ocaml/lib opam/hacl-star-raw
cp -r ocaml/lib_gen opam/hacl-star-raw
cp ocaml/Makefile opam/hacl-star-raw
cp ocaml/ctypes.depend opam/hacl-star-raw
cp ocaml/META opam/hacl-star-raw
cp ocaml/hacl-star-raw.opam opam

cp -r ocaml/hacl-star opam/

make -C opam/hacl-star-raw libhacl.dylib libhacl_static.a
# We need to pick up the environment variables from the cmake build for opam
source opam/hacl-star-raw/build/cached-config.txt
make -C opam/hacl-star-raw -j
make -C opam/hacl-star-raw -j test
