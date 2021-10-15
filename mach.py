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

from tools.utils import subcommand, argument, json_config, cmake_config, cli, subparsers, mprint as print
from tools.vcs import *
from tools.test import run_tests, test

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
    config_file = json_config()
    if args.file:
        config_file = args.file
    algorithms = []
    if args.algorithms:
        algorithms = re.split(r"\W+", args.algorithms)
    if args.name:
        print("⚠️  Named snapshots aren't implemented yet!")
        exit(1)
    if args.path is None:
        print("⚠️  Please provide an output path with --path!")
        exit(1)
    out_dir = args.path
    if os.path.exists(out_dir):
        if args.clean:
            shutil.rmtree(out_dir)
        else:
            print(
                "⚠️  %s exists! Please remove it or choose a different path." % out_dir)
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


# # XXX: Not needed?
# @subcommand([argument("-f", "--file", help="The config.json file to read.", type=str),
#              argument("-o", "--out", help="The config.cmake file to write.", type=str)])
# def configure(args):
#     """Configure command to configure the cmake build from config.json

#     ⚠️  This will override your config.cmake.

#     This will parse the json config file, build the dependency graph, and write
#     out the cmake config file for the build.
#     It is also used to generate HACL distributions with a subset of
#     algorithms.
#     """
#     config_file = "config/config.json"  # The default config.json file.
#     if args.file:
#         config_file = args.file
#     out_file = "config/config.cmake"  # The default config.cmake file.
#     if args.file:
#         out_file = args.out

#     config = Config(config_file)
#     config.write_cmake_config(out_file)


@subcommand([argument("-c", "--clean", help="Clean before building.", action='store_true'),
             argument("-t", "--test", help="Run tests after building.",
                      action='store_true'),
             argument("-r", "--release", help="Build in release mode.",
                      action='store_true'),
             argument("-a", "--algorithms",
                      help="A list of algorithms to enable. Defaults to all.", type=str),
             argument(
                 "-p", "--target", help="Define compile target for cross compilation.", type=str),
             argument(
                 "-d", "--disable", help="Disable (hardware) features even if available.", type=str),
             argument(
                 "-s", "--sanitizer", help="Enable sanitizers.", type=str),
             argument("-v", "--verbose", help="Make builds verbose.", action='store_true')])
def build(args):
    """Main entry point for building HACL

    For convenience it is possible to run tests right after building using -t.

    Supported cross compilation targets:
        - x64-macos

    Features that can be disabled:
        - vec128 (avx/neon)
        - vec256 (avx2)
        - vale (x64 assembly)

    Supported sanitizers:
        - asan
        - ubsan
    """
    # Verbosity
    verbose = False
    if args.verbose:
        verbose = True

        def vprint(*args, **kwargs):
            print(args, kwargs)
    else:
        vprint = lambda *a, **k: None
    # Set config
    build_config = "Debug"
    if args.release:
        build_config = "Release"

    # Clean if requested
    if args.clean:
        print("Cleaning ...")
        try:
            shutil.rmtree("build")
            os.remove(cmake_config())
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
    config = Config(json_config(), algorithms=algorithms)
    config.write_cmake_config(cmake_config())

    # Set target toolchain if cross compiling
    cmake_args = []
    if args.target:
        if args.target == "x64-macos":
            cmake_args.extend(
                ["-DCMAKE_TOOLCHAIN_FILE=config/x64-darwin.cmake"])
        else:
            print("⚠️  Unknown cross-compilation target \"%s\"" % args.target)
            print("   Available targets: x64-macos")
            exit(1)
    if args.disable:
        features_to_disable = list(
            map(lambda f: "-DDISABLE_"+f.upper()+"=ON", re.split(r"\W+", args.disable)))
        cmake_args.extend(features_to_disable)
    if args.test:
        cmake_args.append("-DENABLE_TESTS=ON")
    if args.sanitizer:
        sanitizers = list(
            map(lambda f: "-DENABLE_"+f.upper()+"=ON", re.split(r"\W+", args.sanitizer)))
        cmake_args.extend(sanitizers)

    # Set ninja arguments
    ninja_args = []
    if verbose:
        ninja_args.append('-v')

    # build
    # '--debug-trycompile'
    cmake_cmd = ['cmake', '-B', 'build']
    cmake_cmd.extend(cmake_args)
    vprint(str(cmake_cmd))
    subprocess.run(cmake_cmd, check=True)
    ninja_cmd = ['ninja', '-f', 'build-%s.ninja' % build_config, '-C', 'build']
    ninja_cmd.extend(ninja_args)
    vprint(str(ninja_cmd))
    subprocess.run(ninja_cmd, check=True)
    print("Build finished.")

    # test if requested
    if args.test:
        run_tests(config)


@subcommand()
def clean():
    """Remove all build and config artifacts"""
    os.rmdir("build")
    os.remove(cmake_config())

# === Boiler plate === #


def main():
    args = cli.parse_args()
    if args.subcommand is None:
        cli.print_help()
    else:
        args.func(args)


if __name__ == '__main__':
    main()
