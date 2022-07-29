#!/bin/bash
#

set -e

declare -a tests=(
	"blake2b"
	"blake2s"
	"chacha20poly1305"
	"ed25519"
	"hmac"
	"p256_ecdh"
	"p256_ecdsa"
	"p256k1_ecdsa"
	"rsapss"
	"sha2"
	"sha3"
	"x25519"
)
 
for test in ${tests[@]}; do
	echo -n "Generating coverage report for ${test}... "
	pushd build/Debug

	mkdir -p coverage/${test}/html
	llvm-profdata merge \
		-sparse ${test}.profraw \
		-o coverage/${test}/${test}.profdata
	llvm-cov export \
		-format lcov \
		--instr-profile coverage/${test}/${test}.profdata \
		${test} \
		../../src/*.c \
		> coverage/${test}/${test}.lcov
	genhtml coverage/${test}/${test}.lcov \
		-o coverage/${test}/html

	popd
	echo "done"
done



