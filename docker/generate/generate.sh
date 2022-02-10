#!/usr/bin/env bash

set -e
set -o pipefail

source ~/.profile
git checkout .
git clean -f
cd hacl-star && git checkout . && git pull && git checkout $1 && cd -
./everest --yes hacl-star pull_projects
./everest --yes pull_vale
./everest --yes FStar pull_projects FStar make --admit -j 4
./everest --yes kremlin pull_projects kremlin make --admit -j 4

NOOPENSSLCHECK=1 OTHERFLAGS="--warn_error -282+16+19 --admit_smt_queries true" \
  OCAMLRUNPARAM=b=1 ./everest --yes hacl-star make --admit -j 2
