from argparse import ArgumentParser, RawTextHelpFormatter
import os
from os.path import join
import subprocess
from pathlib import Path
import sys

# The main parser to attach to with the decorator.
cli = ArgumentParser()
subparsers = cli.add_subparsers(dest="subcommand")


def json_config():
    return os.path.join("config", "config.json")


def cmake_config():
    return os.path.join("config", "config.cmake")


def dep_config():
    return os.path.join("config", "dep_config.json")


def config_check_file():
    return join("config", ".dependency_check")

# FIXME: #10 add config.type (Debug/Release)


def binary_path():
    return os.path.join("build", "Debug")


def absolute_file_paths(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))


def subcommand(args=[], parent=subparsers):
    """Decorator for sub commands."""
    dependency_check()

    def decorator(func):
        parser = parent.add_parser(
            func.__name__, description=func.__doc__, formatter_class=RawTextHelpFormatter)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator


def argument(*name_or_flags, **kwargs):
    """Helper for subcommand decorator"""
    return ([*name_or_flags], kwargs)


def mprint(*args, **kwargs):
    """Print with mach indicators"""
    print(" [mach] "+" ".join(map(str, args)), **kwargs)


def check_cmd(cmd):
    return_code = subprocess.run(
        [cmd, '--version'], capture_output=True).returncode
    if return_code == 0:
        mprint("%s ✅" % cmd, end="  ")
    else:
        print()
        mprint(
            '⚠️  Please make sure that "%s" is installed and in your path.' % (cmd))
        exit(1)


def dependency_check():
    """Check that all necessary commands and dependencies are available."""
    file_exists = os.path.exists(config_check_file())
    if file_exists:
        # Nothing to do here, we checked already.
        return

    mprint("🧶  Dependency checks ...")

    check_cmd('cmake')
    check_cmd("ninja")
    check_cmd("clang")
    print()
    Path(config_check_file()).touch()
