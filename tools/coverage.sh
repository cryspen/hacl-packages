#!/bin/bash
#

set -e

echo "[!] Generating coverage report ... "
pushd build/Debug

mkdir -p coverage/full/html
llvm-profdata merge -sparse *.profraw -o coverage/full/full.profdata
llvm-cov export \
	-format lcov \
	--instr-profile coverage/full/full.profdata \
	libhacl.so \
	-object "blake2b" \
	-object "blake2s" \
	-object "chacha20poly1305" \
	-object "ed25519" \
	-object "hmac" \
	-object "p256_ecdh" \
	-object "p256_ecdsa" \
	-object "p256k1_ecdsa" \
	-object "rsapss" \
	-object "sha2" \
	-object "sha3" \
	-object "x25519" \
	../../src/ \
	> coverage/full/full.lcov
genhtml coverage/full/full.lcov -o coverage/full/html

popd
echo "[!] ... done"
