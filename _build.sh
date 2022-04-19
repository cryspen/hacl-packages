#!/usr/bin/env bash
set -e

printf "\n ! THIS IS A COMPLETE BUT UNCONFIGURABLE BUILD !\n"
printf " ! USE ./mach FOR MORE OPTIONS                 !\n\n"

cp config/default_config.cmake config/config.cmake
cmake -B build -G"Ninja Multi-Config"
ninja -f build-Release.ninja -C build
