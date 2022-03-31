#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

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


def cmake_generated_config():
    return os.path.join("config", "cached-config.txt")


def dep_config():
    return os.path.join("config", "dep_config.json")


def config_check_file():
    return join("config", ".dependency_check")

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
    mprint("Found ", end="")
    return_code = subprocess.run(
        [cmd, '--version'], capture_output=True).returncode
    if return_code == 0:
        print("%s" % cmd, end="  ")
    else:
        print()
        mprint(
            '! Please make sure that "%s" is installed and in your path.' % (cmd))
        exit(1)


def dependency_check():
    """Check that all necessary commands and dependencies are available."""
    file_exists = os.path.exists(config_check_file())
    if file_exists:
        # Nothing to do here, we checked already.
        return

    mprint("Dependency checks ...")

    check_cmd('cmake')
    check_cmd("ninja")
    check_cmd("clang")
    print()
    Path(config_check_file()).touch()
