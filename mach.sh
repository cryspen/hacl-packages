#!/usr/bin/env bash
#
# Helper script to build and test evercrypt with CMake, ctest, and ninja.

set -e -x

# Set global variables.
cwd=$(cd $(dirname $0); pwd -P)
build_dir="$cwd/build"

## Build variables.
full=0 # enable all available features
test=0 # run tests; build before if necessary
options=""
config="Debug" # The configuration to use; defaults to Debug

# Display help
show_help()
{
    echo "Usage: mach.sh [-h] [-c] [-cc] [--full] [--test] [--release]"
    echo ""
    echo "Helper script to build and test evercrypt with CMake, ctest, and ninja."
    echo ""
    echo "Options:"
    echo ""
    echo "    -h        display this help and exit"
    echo "    -c        clean before build"
    echo "    -cc       only clean"
    echo "    --full    enable all available features"
    echo "    --test    run tests through ctest; build before if necessary"
    echo "    --release release builds and tests"
}

# Parse command line arguments.
all_args=("$@")
while [ $# -gt 0 ]; do
    case "$1" in
        -c) clean=1 ;;
        -cc) clean=1; clean_only=1 ;;
        --full) full=1 ;;
        --test) test=1 ;;
        --release) config="Release" ;;
        *) display_help; exit 2 ;;
    esac
    shift
done

if [[ "$clean" = 1 ]]; then
    echo " [mach] Cleaning ..."
    rm -rf $build_dir
fi
if [[ "$clean_only" = 1 ]]; then
    echo " [mach] Finished cleaning. I'm done."
    exit 0
fi

# Create the build directory if it does not exist already.
mkdir -p $build_dir

# Set all feature options if requested
if [[ "$full" = 1 ]]; then
    echo " [mach] Enabling all features ..."
    options="$options -DAVX2=ON"
fi

# Run cmake and ninja
cd $build_dir
cmake $options ../
ninja -f build-$config.ninja
if [[ "$test" = 1 ]]; then
    echo " [mach] Run tests ..."
    ctest -C $config
fi
cd -
