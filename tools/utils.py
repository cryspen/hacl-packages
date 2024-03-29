#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import os
import subprocess
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from os.path import join
from pathlib import Path

# The main parser to attach to with the decorator.
cli = ArgumentParser()
subparsers = cli.add_subparsers(dest="subcommand")


def json_config():
    return os.path.join("config", "config.json")


def cmake_config():
    return os.path.join("build", "config.cmake")


def cmake_generated_config():
    return os.path.join("build", "cached-config.txt")


def dep_config():
    return os.path.join("build", "dep_config.json")


def config_check_file():
    return join("build", ".dependency_check")


def config_cache():
    return os.path.join("build", ".cache")


# FIXME: #10 add config.type (Debug/Release)


def cwd():
    return os.path.dirname(os.path.realpath(__file__))


def binary_path(target):
    return os.path.join("build", target)


def absolute_file_paths(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))


def subcommand(args=[], parent=subparsers):
    """Decorator for sub commands."""
    dependency_check()

    def decorator(func):
        parser = parent.add_parser(
            func.__name__,
            description=func.__doc__,
            formatter_class=RawTextHelpFormatter,
        )
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)

    return decorator


def argument(*name_or_flags, **kwargs):
    """Helper for subcommand decorator"""
    return ([*name_or_flags], kwargs)


def mprint(*args, **kwargs):
    """Print with mach indicators"""
    print(" [mach] " + " ".join(map(str, args)), **kwargs)


def check_cmd(cmd, flag="--version"):
    mprint(f"Probing for {cmd}: ", end="")
    try:
        subprocess.check_call(
            [cmd, flag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"Found")
    except:
        print("Not found (!)")
        mprint(f'Error: Please make sure that "{cmd}" is installed and in your PATH.')
        exit(1)


def dependency_check():
    """Check that all necessary commands and dependencies are available."""
    file_exists = os.path.exists(config_check_file())
    if file_exists:
        # Nothing to do here, we checked already.
        return

    mprint("Dependency checks ...")

    check_cmd("cmake")
    check_cmd("ninja")
    # XXX: check for a compiler
    # check_cmd("clang")
    print()
    if not os.path.exists("build"):
        os.mkdir("build")
    Path(config_check_file()).touch()


def coverage_dependency_check():
    """
    Check that `lcov` and friends are installed (and callable).
    """

    check_cmd("lcov")
    check_cmd("llvm-profdata", flag="--help")
    check_cmd("llvm-cov")
    check_cmd("genhtml")
    print()
