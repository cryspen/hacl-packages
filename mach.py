#!/usr/bin/env python3
#
# Generate other snapshots of the source code
#
#     The code snapshots are configured and can be built.
#     However, we don't provide any helpers to do so.
#     Algorithms and features that should be supported
#     must be provided as input.


import subprocess
import re
import json
import os
import shutil
from tools.configure import Config

from tools.utils import *
from tools.vcs import *

# === SUBCOMMANDS === #


@subcommand([argument("-f", "--file", help="The config.json file to read.", type=str),
             argument("-p", "--path",
                      help="The path to write the snapshot to.", type=str),
             argument("-n", "--name",
                      help="Name of the named snapshot.", type=str),
             argument("-a", "--algorithms",
                      help="The algorithms to include in the snapshot.", type=str),
             argument("-c", "--clean",
                      help="Clean the path if it exists.", action='store_true')])
def snapshot(args):
    """Generate a snapshot with the requested distribution

    By default config.json is used. This should not be changed unless you know
    what you are doing!

    There are two different types of snapshots: named snapshots and algorithm-based

    Available named snapshots (TBD):
        - Mozilla
    """
    config_file = "config/config.json"  # The default config.json file.
    if args.file:
        config_file = args.file
    algorithms = []
    if args.algorithms:
        algorithms = re.split(r"\W+", args.algorithms)
    if args.name:
        print(" [mach] ⚠️  Named snapshots aren't implemented yet!")
        exit(1)
    if args.path is None:
        print(" [mach] ⚠️  Please provide an output path with --path!")
        exit(1)
    out_dir = args.path
    if os.path.exists(out_dir):
        if args.clean:
            shutil.rmtree(out_dir)
        else:
            print(
                " [mach] ⚠️  %s exists! Please remove it or choose a different path." % out_dir)
            exit(1)
    os.mkdir(out_dir)
    config = Config(config_file, algorithms=algorithms)

    # Write snapshot
    # First the source files
    dst_src_dir = join(out_dir, "src")
    os.mkdir(dst_src_dir)
    for source_file in config.source_files():
        f = os.path.abspath(source_file)
        shutil.copy(f, dst_src_dir)
    
    # Now the header files
    # TODO: use config.header_files()


# XXX: Not needed?
@subcommand([argument("-f", "--file", help="The config.json file to read.", type=str),
             argument("-o", "--out", help="The config.cmake file to write.", type=str)])
def configure(args):
    """Configure command to configure the cmake build from config.json

    ⚠️  This will override your config.cmake.

    This will parse the json config file, build the dependency graph, and write
    out the cmake config file for the build.
    It is also used to generate hacl or evercrypt distributions with a subset of
    algorithms.
    """
    config_file = "config/config.json"  # The default config.json file.
    if args.file:
        config_file = args.file
    out_file = "config/config.cmake"  # The default config.cmake file.
    if args.file:
        out_file = args.out

    config = Config(config_file)
    config.write_cmake_config(out_file)


@subcommand([argument("-c", "--clean", help="Clean before building.", action='store_true'),
             argument("-t", "--test", help="Run tests after building.",
                      action='store_true'),
             argument("-r", "--release", help="Build in release mode.",
                      action='store_true'),
             argument("-a", "--algorithms", help="A list of algorithms to enable. Defaults to all.", type=str),
             argument("-p", "--target", help="Define compile target for cross compilation", type=str)])
def build(args):
    """Main entry point for building Evercrypt

    For convenience it is possible to run tests right after building using -t.

    Supported cross compilation targets:
        - x64-macos
    """
    # Set config
    build_config = "Debug"
    if args.release:
        build_config = "Release"

    # Clean if requested
    if args.clean:
        print(" [mach] Cleaning ...")
        try:
            shutil.rmtree("build")
            os.remove("config/config.cmake")
        except:
            pass  # We don't really care
    try:
        os.mkdir("build")
    except:
        pass  # We ignore the error if the directory exists already

    # Generate config.cmake using the algorithms argument if any given
    algorithms = []
    if args.algorithms:
        algorithms = re.split(r"\W+", args.algorithms)
    config = Config("config/config.json", algorithms=algorithms)
    config.write_cmake_config("config/config.cmake")

    # Set target toolchain if cross compiling
    cmake_args = []
    if args.target:
        cmake_args.extend(["-DCMAKE_TOOLCHAIN_FILE=config/x64-darwin.cmake"])

    # build
    cmake_cmd = ['cmake', '--debug-trycompile', '-B', 'build']
    cmake_cmd.extend(cmake_args)
    subprocess.run(cmake_cmd, check=True)
    subprocess.run(['ninja', '-v', '-f', 'build-%s.ninja' % build_config, '-C', 'build'], check=True)
    print(" [mach] Build finished.")

    # test if requested
    if args.test:
        # --build-two-config
        subprocess.run(['ctest', '-C', build_config, '--test-dir', 'build'], check=True)


@subcommand()
def clean():
    """Remove all build and config artifacts"""
    os.rmdir("build")
    os.remove("config/config.cmake")

# === Boiler plate === #


def main():
    args = cli.parse_args()
    if args.subcommand is None:
        cli.print_help()
    else:
        args.func(args)


if __name__ == '__main__':
    main()
