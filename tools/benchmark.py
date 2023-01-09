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


def compare_benchmarks(benchmarks, path_new, path_old):
    print("Comparing benchmarks ...")

    if not os.path.exists(path_new) or not os.path.exists(path_old):
        print(
            "! Build missing! Please build both revisions first: `./mach build --release --benchmarks`. Aborting!"
        )
        exit(1)
    if not os.path.exists("build/benchmark-src"):
        print("! gbenchmark missing! Aborting!")
        exit(1)

    compare = "./build/benchmark-src/tools/compare.py"

    for algorithm in benchmarks:
        for benchmark in benchmarks[algorithm]:

            file_name = Path(benchmark).stem
            file_name_new = os.path.join(path_new, file_name + "_benchmark")
            file_name_old = os.path.join(path_old, file_name + "_benchmark")
            if sys.platform == "win32":
                file_name_new += ".exe"
                file_name_old += ".exe"

            # Compare benchmarks that exist in both directories:
            # - Fail if a benchmark is missing in the newer directory.
            # - Ignore if a benchmark is missing in the older directory.
            if not os.path.exists(file_name_new):
                print("! Benchmark '%s' doesn't exist. Aborting!" % (file_name_new))
                print("   Running this benchmark requires a build first.")
                print("   See mach build --help")
                exit(1)
            if not os.path.exists(file_name_old):
                print("! Benchmark '%s' doesn't exist!" % (file_name_old))
                continue
            out_path = os.path.join(path_new, file_name + "_benchmark.json")
            benchmark_cmd = [
                compare,
                "-d",
                os.path.join(".", out_path),
                "benchmarks",
                file_name_old,
                os.path.join(".", file_name_new),
            ]
            print(" ".join(benchmark_cmd))
            subprocess.run(benchmark_cmd)

    threshold = 0.2
    fail = False
    for algorithm in benchmarks:
        for benchmark in benchmarks[algorithm]:
            file_name = Path(benchmark).stem
            out_path = os.path.join(path_new, file_name + "_benchmark.json")
            if not os.path.exists(out_path):
                continue
            f = open(out_path)
            data = json.load(f)
            # For each benchmark, the result is the overall CPU-time evolution
            result = data[-1]["measurements"][0]["cpu"]
            print("{:20} {:+0.2f}".format(file_name, result))
            # If one result is greater than the threshold, the command fails
            if result > threshold:
                fail = True
    if fail:
        print("! Threshold exceeded!")
        exit(1)


@subcommand(
    [
        argument(
            "-v", "--verbose", help="Make benchmarks verbose.", action="store_true"
        ),
        argument("--compare", help="Compare against an older revision.", type=str),
    ]
)
def benchmark(args):
    """Benchmark HACL"""

    # read file
    with open(json_config(), "r") as f:
        data = f.read()

    # parse file
    config = json.loads(data)

    if args.compare:
        compare_benchmarks(
            config["benchmarks"],
            binary_path("Release"),
            os.path.join(args.compare, binary_path("Release")),
        )
    else:
        run_benchmarks(config["benchmarks"], "Release")
