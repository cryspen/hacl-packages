#!/usr/bin/env bash
set -e

echo " ! THIS IS A COMPLETE BUT UNCONFIGURABLE BUILD !"
echo " ! USE ./mach INSTEAD                          !"

cmake -B build -G"Ninja Multi-Config"
ninja -f build-Release.ninja -C build
