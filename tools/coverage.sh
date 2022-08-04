#!/bin/bash
#

set -e

echo "[!] Generating coverage report ... "
pushd build/Debug

hacl=""

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
	hacl=libhacl.so
else
	hacl=libhacl.dylib
fi

mkdir -p coverage/full/html
llvm-profdata merge -sparse *.profraw -o coverage/full/full.profdata
llvm-cov export \
	-format lcov \
	--instr-profile coverage/full/full.profdata \
	$hacl \
	../../src/ \
	> coverage/full/full.lcov
genhtml coverage/full/full.lcov -o coverage/full/html

popd
echo "[!] ... done"
