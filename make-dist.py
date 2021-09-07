#!/usr/bin/env python3
#
# Generate other snapshots of the source code
#
#     The code snapshots are configured and can be built.
#     However, we don't provide any helpers to do so.
#     Algorithms and features that should be supported
#     must be provided as input.   


from argparse import ArgumentParser
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
             argument("-f", "--features", help="The list of hardware features to include.", type=str),
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
    config_file = "config.json" # The default config file.
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
            if hacl_file in hacl_dependencies:
                features_for_file = hacl_dependencies[hacl_file]
                print("\tdependencies: %s" % (features_for_file))


# Boiler plate
def main():
    args = cli.parse_args()
    if args.subcommand is None:
        cli.print_help()
    else:
        args.func(args)

if __name__ == '__main__':
    main()
