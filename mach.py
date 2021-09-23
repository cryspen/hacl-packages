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

from tools.utils import *
from tools.vcs import *


# === HELPER FUNCTIONS === #


def dependencies(algorithm, source_file):
    """Collect dependencies for a given c file

    Use `clang -MM` to collect dependencies for a given c file assuming header
    and source files are named the same.
    """
    # Build dependency graph
    result = subprocess.run(
        'clang -I include -I build -I kremlin/include/ -I kremlin/kremlib/dist/minimal -MM src/'+source_file,
        stdout=subprocess.PIPE,
        shell=True,
        check=True)
    stdout = result.stdout.decode('utf-8')

    files = []
    for line in stdout.splitlines():
        # Remove object file and the c file itself
        line = re.sub("(\w*).o: src/(\w*).c", "", line)
        line = line.strip()
        line = line.split(' ')
        try:
            line.remove("\\")
        except:
            # This is fine
            pass
        files.extend(line)

    # Get all source files in src/
    result = subprocess.run(
        'ls -1a src/*.c', stdout=subprocess.PIPE, shell=True)
    source_files = result.stdout.decode('utf-8')
    source_files = source_files.splitlines()
    # remove src/ and .c
    source_files = list(map(lambda s: s[4:-2], source_files))

    # Now let's collect the c files from the included headers
    deps = []
    for include in files:
        # Get the file name from the path (could be done more efficiently before)
        include_match = re.match(
            "^(.*/)?(?:$|(.+?)(?:(\.[^.]*$)|$))", include)
        include = include_match.group(2)
        # Only add the dependency if there's a corresponding source file.
        if include in source_files:
            deps.append("src/"+include+".c")
    return deps


def run_configure(config_file, out_file, algorithms=[]):
    """Configure the build and write config.cmake

    This will parse the json config file, build the dependency graph, and write
    out the cmake config file for the build.
    It is also used to generate hacl or evercrypt distributions with a subset of
    algorithms.
    """
    print(" [mach] Using %s to configure %s" % (config_file, out_file))
    print(" [mach] ⚠️  THIS OVERRIDES %s. (But it's too late now ... )" % out_file)

    # read file
    with open(config_file, 'r') as f:
        data = f.read()

    # parse file
    config = json.loads(data)
    kremlin_files = config["kremlin_sources"]
    hacl_files = config["hacl_sources"]
    evercrypt_files = config["evercrypt_sources"]
    features = config["features"]
    tests = config["tests"]

    # Filter algorithms in hacl_files
    # In the default case (empty list of algorithms) we don't do anything.
    if len(algorithms) != 0:
        for a, v in list(hacl_files.items()):
            if not a in algorithms:
                del hacl_files[a]

    # Collect dependencies for the hacl files.
    hacl_compile_files = {}
    for a in hacl_files:
        for source_file in hacl_files[a]:
            hacl_compile_files[a] = dependencies(a, source_file)

    # Collect features, inverting the features map
    cpu_features = {}
    for file in features:
        for feature in features[file]:
            if feature in cpu_features:
                cpu_features[feature].append(file)
            else:
                cpu_features[feature] = [file]

    # TODO: evercrypt dependencies.

    with open(out_file, 'w') as out:
        if len(kremlin_files) > 0:
            out.write("set(KREMLIN_FILES %s)\n" %
                      " ".join(f for f in kremlin_files))

        out.write("set(ALGORITHMS %s)\n" % " ".join(a for a in hacl_files))
        # for a in hacl_files:
        #     out.write("option(%s \"\" ON)\n" % a)
        out.write("set(ALGORITHM_HACL_FILES %s)\n" %
                  " ".join("HACL_FILES_"+a for a in hacl_files))

        for a in hacl_compile_files:
            out.write("set(HACL_FILES_%s %s)\n" %
                      (a, " ".join("${PROJECT_SOURCE_DIR}/"+f for f in hacl_compile_files[a])))

        out.write("set(ALGORITHM_EVERCRYPT_FILES %s)\n" %
                  " ".join("EVERCRYPT_FILES_"+a for a in evercrypt_files))
        for a in evercrypt_files:
            out.write("set(EVERCRYPT_FILES_%s %s)\n" %
                      (a, " ".join("${PROJECT_SOURCE_DIR}/"+f for f in evercrypt_files[a])))

        for f in features:
            out.write("set(REQUIRED_FEATURES_%s %s)\n" % (os.path.splitext(
                f)[0], " ".join(feature for feature in features[f])))

        for f in cpu_features:
            out.write("set(CPU_FEATURE_%s %s)\n" % (os.path.splitext(
                f)[0], " ".join("${PROJECT_SOURCE_DIR}/src/"+file for file in cpu_features[f])))

        out.write("set(ALGORITHM_TEST_FILES %s)\n" %
                  " ".join("TEST_FILES_"+a for a in tests))
        for a in tests:
            out.write("set(TEST_FILES_%s %s)\n" %
                      (a, " ".join(f for f in tests[a])))

# === SUBCOMMANDS === #


@subcommand([argument("-f", "--file", help="The config.json file to read.", type=str),
             argument("-o", "--out", help="The config.cmake file to write.", type=str)])
def configure(args):
    """Configure sub command to configure the cmake build from config.json

    ⚠️  This will override your config.cmake.
    """
    config_file = "config/config.json"  # The default config.json file.
    if args.file:
        config_file = args.file
    out_file = "config/config.cmake"  # The default config.cmake file.
    if args.file:
        out_file = args.out

    run_configure(config_file, out_file)


@subcommand([argument("-c", "--clean", help="Clean before building.", action='store_true'),
             argument("-t", "--test", help="Run tests after building.",
                      action='store_true'),
             argument("-r", "--release", help="Build in release mode.",
                      action='store_true'),
             argument("-a", "--algorithms", help="A list of algorithms to enable. Defaults to all.", type=str)])
def build(args):
    """Main entry point for building Evercrypt

    For convenience it is possible to run tests right after building using -t.
    """
    # Set config
    config = "Debug"
    if args.release:
        config = "Release"

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
    run_configure("config/config.json", "config/config.cmake",
                  algorithms=algorithms)

    # build
    os.chdir("build")
    subprocess.run(['cmake', '--debug-trycompile', '../'], check=True)
    subprocess.run(['ninja', '-f', 'build-%s.ninja' % config], check=True)
    print(" [mach] Build finished.")

    # test if requested
    if args.test:
        subprocess.run(['ctest', '-C', config], check=True)


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
