import json
import os
import re
import subprocess
from tools.configure import Config
from tools.utils import subcommand, argument, cli, subparsers, mprint as print, binary_path, json_config

from os.path import join
from pathlib import Path


def run_tests(tests, test_args=[], algorithms=[]):
    print("Running tests 🏃")
    if not os.path.exists(binary_path()):
        print("⚠️  Nothing is built! Please build first. Aborting!")
        exit(1)
    os.chdir(binary_path())
    my_env = dict(os.environ)
    my_env["TEST_DIR"] = join(os.getcwd(), "..", "..", "tests")
    for algorithm in tests:
        for test in tests[algorithm]:
            test_name = os.path.splitext(test)[0]
            if len(algorithms) == 0 or test_name in algorithms or algorithm in algorithms:
                file_name = Path(test).stem
                if not os.path.exists(file_name):
                    print("⚠️  Test '%s' doesn't exist. Aborting!" %
                          (file_name))
                    print("   Running this test requires a build first.")
                    print("   See mach.py build --help")
                    exit(1)
                test_cmd = [join(".", file_name)]
                test_cmd.extend(test_args)
                print(" ".join(test_cmd))
                subprocess.run(test_cmd, check=True, shell=True, env=my_env)

# TODO: add arguments (pass through gtest arguments and easy filters)


@subcommand([argument("-a", "--algorithms",
                      help="The algorithms to test.", type=str)])
def test(args):
    """Test HACL*
    """
    algorithms = []
    if args.algorithms:
        algorithms = re.split(r"\W+", args.algorithms)

    # read file
    with open(json_config(), 'r') as f:
        data = f.read()

    # parse file
    config = json.loads(data)
    # config = Config(json_config(), algorithms=algorithms)
    run_tests(config['tests'], algorithms=algorithms)
