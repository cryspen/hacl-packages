from argparse import ArgumentParser, RawTextHelpFormatter

# The main parser to attach to with the decorator.
cli = ArgumentParser()
subparsers = cli.add_subparsers(dest="subcommand")


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
