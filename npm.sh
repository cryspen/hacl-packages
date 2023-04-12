#! /bin/sh

set -e

rm -rf npm

mkdir -p npm
cp src/wasm/*.wasm src/wasm/layouts.json src/wasm/INFO.txt src/wasm/shell.js src/wasm/loader.js npm
cp js/* npm
