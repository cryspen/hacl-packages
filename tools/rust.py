
#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import shutil
import os
import subprocess
from os.path import join

from tools.utils import subcommand, argument, cli, subparsers, mprint as print, cwd


root = join(cwd(), "..")
package_path = join(root, "rust", ".c")


def copy_tree(dir):
    shutil.copytree(join(root, dir), join(package_path, dir))


def prepare():
    # Always start fresh.
    print("Copying C sources for Rust build into: "+package_path)
    shutil.rmtree(package_path, ignore_errors=True)
    os.mkdir(package_path)

    # Copy over all the C code
    copy_tree("config")
    copy_tree("src")
    copy_tree("vale")
    copy_tree("karamel")
    copy_tree("include")
    shutil.copyfile(join(package_path, "config", "default_config.cmake"), join(
        package_path, "config", "config.cmake"))
    shutil.copyfile(join(root, "CMakeLists.txt"),
                    join(package_path, "CMakeLists.txt"))

    print("Set up C sources: %s" % (os.listdir(package_path)))


@subcommand([argument("-p", "--package",
                      help="Package the Rust bindings.",  action='store_true'),
             argument("-t", "--test",
                      help="Run Rust tests.",  action='store_true'),
             argument("-b", "--build",
                      help="Build Rust.",  action='store_true'),
             argument("-v", "--verbose", help="Make it verbose.",
                      action='store_true')])
def rust(args):
    """HACL Rust Subcommand

    This command allows you to handle the Rust bindings for HACL.
    """
    prepare()
    if args.package:
        print("Packaging is not implemented yet")
        # if args.verbose:
        #     cargo_cmd += ' -v'
        # cargo_cmd = 'cargo publish --dry-run --allow-dirty --manifest-path ' + cargo_path
    if args.test:
        # Run tests
        cargo_path = join(root, "rust", "Cargo.toml")
        cargo_cmd = 'cargo test --manifest-path ' + cargo_path
        if args.verbose:
            cargo_cmd += ' -v'
        subprocess.run(cargo_cmd, check=True, shell=True)
    if args.build:
        # Build
        cargo_path = join(root, "rust", "Cargo.toml")
        cargo_cmd = 'cargo build --manifest-path ' + cargo_path
        if args.verbose:
            cargo_cmd += ' -v'
        subprocess.run(cargo_cmd, check=True, shell=True)
    else:
        print("Only prepared the Rust build, didn't do anything else.")
