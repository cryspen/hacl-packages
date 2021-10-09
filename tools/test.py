import os
import re
import subprocess
from tools.configure import Config
from tools.utils import subcommand, argument, cli, subparsers, mprint as print, binary_path

from os.path import join
from pathlib import Path


def run_tests(config, test_args=[]):
    print("Running tests 🏃🏻‍♀️")
    os.chdir(binary_path())
    for algorithm in config.tests:
        for test in config.tests[algorithm]:
            file_name = Path(test).stem
            test_cmd = ['./'+file_name]
            test_cmd.extend(test_args)
            print(" ".join(test_cmd))
            subprocess.run(test_cmd, check=True)

# TODO: add arguments (pass through gtest arguments and easy filters)


@subcommand([argument("-f", "--file", help="The config.json file to read.", type=str),
             argument("-a", "--algorithms",
                      help="The algorithms to include in the snapshot.", type=str)])
def test(args):
    """Test HACL*
    """
    config_file = join(
        "config", "config.json")  # The default config.json file.
    if args.file:
        config_file = args.file
    algorithms = []
    if args.algorithms:
        algorithms = re.split(r"\W+", args.algorithms)
    config = Config(config_file, algorithms=algorithms)
    run_tests(config)
