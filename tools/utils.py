from argparse import ArgumentParser, RawTextHelpFormatter
import os

# The main parser to attach to with the decorator.
cli = ArgumentParser()
subparsers = cli.add_subparsers(dest="subcommand")

def json_config():
    return os.path.join("config", "config.json")

def cmake_config():
    return os.path.join("config", "config.cmake")

# FIXME: add config.type (Debug/Release)
def binary_path():
    return os.path.join("build", "Debug")

def subcommand(args=[], parent=subparsers):
    """Decorator for sub commands."""
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
