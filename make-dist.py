#!/usr/bin/env python3
#
# Generate other snapshots of the source code
#
#     The code snapshots are configured and can be built.
#     However, we don't provide any helpers to do so.
#     Algorithms and features that should be supported
#     must be provided as input.


from argparse import ArgumentParser
import subprocess
import re
import json

# The main parser to attach to with the decorator.
cli = ArgumentParser()
subparsers = cli.add_subparsers(dest="subcommand")

# Decorator for sub commands.


def subcommand(args=[], parent=subparsers):
    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator

# Helper for subcommand decorator


def argument(*name_or_flags, **kwargs):
    return ([*name_or_flags], kwargs)

# Sub command for building a snapshot with a subset of algorithms
#
# The config should be read from config.json.


@subcommand([argument("-a", "--algorithms", help="The list of algorithms to include.", type=str),
             argument("-f", "--features",
                      help="The list of hardware features to include.", type=str),
             argument("-b", "--hacl", help="Only enable hacl* without evercrypt.", action="store_true")])
def snapshot(args):
    # Parsing arguments to decide what to put into the snapshot.
    if args.algorithms:
        algorithms = [s.strip().lower() for s in args.algorithms.split(",")]
    else:
        algorithms = []
    print("Enabling algorithms", algorithms)
    if args.features:
        features = [s.strip().lower() for s in args.features.split(",")]
    else:
        features = []
    print("Enabling features", features)
    hacl = args.hacl
    if hacl:
        print("Enabling only hacl* without evercrypt")

    # The HACL source code files
    hacl_sources = {
        "aes": ["Hacl_AES.c"],
        "blake2b": ["Hacl_Blake2b_32.c", "Hacl_Blake2b_256.c"],
        "chacha20poly1305": ["Hacl_Chacha20Poly1305_32.c", "Hacl_Chacha20Poly1305_128.c", "Hacl_Chacha20Poly1305_256.c"],
    }
    # Features required by each file.
    hacl_features = {
        "Hacl_AES.c": ["aesni"],
        "Hacl_Blake2b_32.c": [],
        "Hacl_Blake2b_256.c": ["avx2"],
        "Hacl_Chacha20Poly1305_32.c": [],
        "Hacl_Chacha20Poly1305_128.c": ["avx"],
        "Hacl_Chacha20Poly1305_256.c": ["avx2"],

    }

    # Get the sources and dependencies required by the requested
    # algorithms and features.
    enabled_sources = []
    for a in algorithms:
        if a in hacl_sources:
            # Check if the required features were requested as well.
            for hacl_file in hacl_sources[a]:
                required_features = hacl_features[hacl_file]
                available = True
                for required_feature in required_features:
                    if not required_feature in features:
                        available = False
                        break
                if available:
                    enabled_sources.append(hacl_file)
        else:
            print("\nAborting")
            print("  Unknown algorithm '%s'\n" % a)
            exit(1)

    print("sources: ", enabled_sources)

# Building and pretty printing the dependency graph


@subcommand([argument("-f", "--file", help="The config file to read.", type=str)])
def graph(args):
    config_file = "config.json"  # The default config file.
    if args.file:
        config_file = args.file
    print("Doing graph with config file", config_file)

    # read file
    with open(config_file, 'r') as f:
        data = f.read()

    # parse file
    config = json.loads(data)

    # get hacl* files, dependencies, and features
    hacl_files = config["hacl_sources"]
    hacl_dependencies = config["hacl_dependencies"]
    hacl_features = config["hacl_features"]
    algorithms = config["algorithms"]
    features = config["features"]

    for algorithm in algorithms:
        files_for_algorithm = hacl_files[algorithm]
        print("files for %s: %s" % (algorithm, files_for_algorithm))

        for hacl_file in files_for_algorithm:
            # Collect dependencies for each file.
            all_files = []
            if hacl_file in hacl_dependencies:
                all_files = hacl_dependencies[hacl_file]
                print("\tdependencies: %s" % (all_files))

            all_files.insert(0, hacl_file)
            # Collect features required for each file.
            for file in all_files:
                if file in hacl_features:
                    features_for_file = hacl_features[file]
                    print("\tfeatures for %s: %s" % (file, features_for_file))

# Building and pretty printing the dependency graph


@subcommand()
def dep(args):
    # Get all source files in src/
    result = subprocess.run(
        'ls -1a src/*.c', stdout=subprocess.PIPE, shell=True)
    source_files = result.stdout.decode('utf-8')
    source_files = source_files.splitlines()
    # remove src/ and .c
    source_files = list(map(lambda s: s[4:-2], source_files))

    # Build dependency graph
    result = subprocess.run(
        'clang -I include -I build -I kremlin/include/ -I kremlin/kremlib/dist/minimal -MM src/*.c', stdout=subprocess.PIPE, shell=True)
    stdout = result.stdout.decode('utf-8')
    files = []
    file = {}
    for line in stdout.splitlines():
        # New c file
        matched_line = re.match("(\w*).o: src/(\w*).c (.*.h) \\\\", line)
        if matched_line != None:
            if file.__len__() != 0:
                files.append(file)
            file_name = matched_line.group(1)
            # Sanity check: The c file has the same name as the object
            assert(file_name == matched_line.group(2))
            first_line = matched_line.group(3).strip()
            file = [file_name]
            file.extend(first_line.split(' '))
        else:
            line = line.strip()
            line = line.split(' ')
            try:
                line.remove("\\")
            except:
                # This is fine
                pass
            file.extend(line)

    # Now let's collect the c files from the included headers
    deps = {}
    for f in files:
        # print(f)
        file_name = f[0]
        includes = f[1:]

        dependencies = []
        for include in includes:
            # Get the file name from the path (could be done more efficiently before)
            include_match = re.match(
                "^(.*/)?(?:$|(.+?)(?:(\.[^.]*$)|$))", include)
            include = include_match.group(2)
            # print("%s == %s" % (include, source_files[0]))
            if include in source_files:
                dependencies.append("src/"+include+".c")
        deps[file_name] = dependencies
    for d in deps:
        print("%s:\n\t%s" % (d, deps[d]))

# Boiler plate


def main():
    args = cli.parse_args()
    if args.subcommand is None:
        cli.print_help()
    else:
        args.func(args)


if __name__ == '__main__':
    main()
