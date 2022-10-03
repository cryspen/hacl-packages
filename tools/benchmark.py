import json
import os
from pathlib import Path
import subprocess
import sys
from tools.utils import (
    binary_path,
    cli,
    json_config,
    mprint as print,
    subcommand,
    argument,
)


def run_benchmarks(benchmarks, bin_path):
    print("Running benchmarks ...")
    if not os.path.exists(binary_path(bin_path)):
        print("! Nothing is built! Please build first. Aborting!")
        exit(1)
    dir_backup = os.getcwd()
    os.chdir(binary_path(bin_path))

    for algorithm in benchmarks:
        for benchmark in benchmarks[algorithm]:

            file_name = Path(benchmark).stem
            file_name += "_benchmark"
            if sys.platform == "win32":
                file_name += ".exe"
            if not os.path.exists(file_name):
                print("! Benchmark '%s' doesn't exist. Aborting!" % (file_name))
                print("   Running this benchmark requires a build first.")
                print("   See mach build --help")
                exit(1)
            benchmark_cmd = [os.path.join(".", file_name)]
            print(" ".join(benchmark_cmd))
            subprocess.run(benchmark_cmd, check=True)


@subcommand(
    [
        argument(
            "-v", "--verbose", help="Make benchmarks verbose.", action="store_true"
        ),
    ]
)
def benchmarks(args):
    """Benchmark HACL"""

    # read file
    with open(json_config(), "r") as f:
        data = f.read()

    # parse file
    config = json.loads(data)

    run_benchmarks(config["benchmarks"], "Release")
