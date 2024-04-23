#!/usr/bin/env bash

set -e
set -o pipefail

mkdir -p hacl
cp ../src/Hacl_Hash_SHA3.c hacl/
cp ../include/Hacl_Hash_SHA3.h include/
cp ../include/internal/Hacl_Hash_SHA3.h include/internal/
cp ../src/Hacl_Hash_SHA3_Scalar.c hacl/
cp ../include/Hacl_Hash_SHA3_Scalar.h include/
cp ../include/internal/Hacl_Hash_SHA3_Scalar.h include/internal/
cp ../include/Hacl_Streaming_Types.h include/
touch include/LowStar_Ignore.h
cp -r ../karamel/include/* include/
cp -r ../karamel/krmllib/dist/minimal/* include/
tar cjvf standalone-kyber-$(date '+%Y%M%d%H%M').tar.bz2 --exclude "src/Libcrux_Kem_Kyber_Kyber768.c" --exclude "mitch-and-sam.sh" --exclude '*.tar.bz2' --exclude 'a.out' *
