#!/usr/bin/env python3
#
#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import json
import os
import pathlib
import re
import shutil
import subprocess
from os.path import join as join_path
from pathlib import Path

from tools.utils import argument, mprint as print, subcommand


def raw_dependencies(src_dir, c_file):
    compiler = os.getenv("CC", "clang")
    include_paths = ["karamel/krmllib/dist/minimal", "karamel/include", src_dir]
    includes = "-I " + " -I ".join(include_paths)
    result = subprocess.run(
        compiler + " " + includes + " -MM " + os.path.join(src_dir, c_file),
        stdout=subprocess.PIPE,
        shell=True,
        check=True,
    )
    return result.stdout.decode("utf-8")


def abs_path(relative):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", relative))


def source_files(directory):
    source_files_abs = []
    source_file_names = []
    for f in os.listdir(directory):
        f = os.path.join(directory, f)
        if os.path.isfile(f) and f[-2:] == ".c":
            source_files_abs.append(os.path.abspath(f))
            source_file_names.append(os.path.basename(f))
    return source_files_abs, source_file_names


def dependencies(src_dir, c_file):
    # Get a list of all source files
    _, source_names = source_files(src_dir)
    raw_deps = raw_dependencies(src_dir, c_file)

    files = []
    for line in raw_deps.splitlines():
        # Remove object file and split the lines
        line = re.sub("(\w*).o: ", "", line)
        line = line.strip()
        line = line.split(" ")
        try:
            line.remove("\\")
        except:
            # This is fine
            pass

        # Drop karamel files.
        line = [file for file in line if not file.startswith("krml")]

        # Sources
        # For source files we only care about the file name. Drop the path.
        line = list(map(lambda file: os.path.basename(file), line))
        # Make them c files.
        line = list(map(lambda file: file[:-2] + ".c", line))
        # If there's a corresponding c file to the header, we need this.
        line = [file for file in line if file in source_names]
        # Make paths absolute
        line = list(map(lambda file: abs_path(os.path.join(src_dir, file)), line))
        files.extend(line)

    file_names = []
    for file in files:
        file_names.append(os.path.basename(file))

    return files, file_names


# Note: This is currently unused but will be used in the future.
#
# def read_config(config_file_name):
#     # read file
#     with open(config_file_name, "r") as f:
#         data = f.read()
#
#     # parse file
#     config = json.loads(data)
#     hacl_files = config["hacl_sources"]
#     vale_files = config["vale_sources"]
#     evercrypt_files = config["evercrypt_sources"]
#
#     # flatten file lists
#     files = []
#     for algorithm in hacl_files:
#         files.extend(map(lambda e: e["file"], hacl_files[algorithm]))
#     for algorithm in vale_files:
#         for platform in vale_files[algorithm]:
#             files.extend(vale_files[algorithm][platform])
#     for algorithm in evercrypt_files:
#         files.extend(evercrypt_files[algorithm])
#     return files


def headers(editions):
    includes = {}
    include_names = {}
    for edition, new_dist_dir, _, _ in editions:
        files = [file for file in os.listdir(new_dist_dir) if file.endswith(".h")]
        include_names[edition] = [os.path.basename(file) for file in files]
        includes[edition] = [
            abs_path(os.path.join(new_dist_dir, file)) for file in files
        ]
    return includes, include_names


def all_files(config_file, editions):
    # required_files = read_config(config_file)

    files = {}
    file_names = {}
    # for edition, new_dist_dir, _, _ in editions:
    #     for file in required_files:
    #         if file.endswith(".c"):
    #             t_files, t_file_names = dependencies(new_dist_dir, file)
    #             if edition in files:
    #                 files[edition].extend(t_files)
    #             else:
    #                 files[edition] = t_files
    #             if edition in file_names:
    #                 file_names[edition].extend(t_file_names)
    #             else:
    #                 file_names[edition] = t_file_names
    for edition, new_dist_dir, _, _ in editions:
        t_files, t_file_names = source_files(new_dist_dir)
        files[edition] = t_files
        file_names[edition] = t_file_names

    includes, include_names = headers(editions)
    # TODO: remove includes we don't care about. The includes list should get
    #       mapped against the `file_names`. However there are includes that we
    #       need but that doesn't match the naming conventions. We have to get
    #       the includes from the `dependencies` analysis as well.

    # remove duplicates
    for edition in files:
        files[edition] = list(dict.fromkeys(files[edition]))
        file_names[edition] = list(dict.fromkeys(file_names[edition]))
        # remove vale
        files[edition] = [file for file in files[edition] if not "Vale" in file]
        file_names[edition] = [
            file for file in file_names[edition] if not "Vale" in file
        ]
        includes[edition] = [file for file in includes[edition] if not "Vale" in file]
        include_names[edition] = [
            file for file in include_names[edition] if not "Vale" in file
        ]

    return files, file_names, includes, include_names


def rm(file):
    if os.path.isfile(file):
        os.remove(file)
    else:
        shutil.rmtree(file, ignore_errors=True)


def clean():
    for filename in os.listdir("src"):
        rm(os.path.join("src", filename))
    for filename in os.listdir("include"):
        rm(os.path.join("include", filename))
    # OCaml
    rm(os.path.join("ocaml", "lib"))
    rm(os.path.join("ocaml", "lib_gen"))
    rm(os.path.join("ocaml", "ctypes.depend"))


def update_hacl(files, includes, editions):
    clean()
    for edition, new_dist_dir, dest, include_dest in editions:
        dest = abs_path(dest)
        print("Reading %s into %s ..." % (new_dist_dir, dest))
        for file in files[edition]:
            pathlib.Path(dest).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, os.path.join(dest, os.path.basename(file)))
        include_dest = abs_path(include_dest)
        for file in includes[edition]:
            pathlib.Path(include_dest).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, os.path.join(include_dest, os.path.basename(file)))
        internal_includes = os.path.join(abs_path(new_dist_dir), "internal")
        dest_internal = os.path.join(include_dest, "internal")
        shutil.copytree(internal_includes, dest_internal)


def update_karamel(new_dist_dir):
    rm("karamel/include")
    rm("karamel/krmllib")
    shutil.copytree(os.path.join(new_dist_dir, "karamel/include"), "karamel/include")
    shutil.copytree(os.path.join(new_dist_dir, "karamel/krmllib"), "karamel/krmllib")


def update_vale(new_dist_dir):
    new_dist_dir = Path(new_dist_dir)

    rm("vale/include")
    os.mkdir("vale/include")

    rm("vale/src")
    os.mkdir("vale/src")

    shutil.copy(
        new_dist_dir.joinpath("gcc-compatible/internal/Vale.h"),
        Path(abs_path("vale/include")).joinpath("Vale.h"),
    )

    shutil.copy(
        new_dist_dir.joinpath("gcc-compatible/Vale.c"),
        Path(abs_path("vale/src")).joinpath("Vale.c"),
    )
    for path in new_dist_dir.joinpath("vale").iterdir():
        if path.is_file():
            shutil.copy(path, Path(abs_path("vale/src")))


@subcommand(
    [
        argument(
            "-s",
            "--hacl-home",
            help="The base directory of the HACL* repository.",
            type=str,
        ),
        argument("--no-vale", help="Don't update Vale.", action="store_true"),
        argument("-v", "--verbose", help="Make it verbose.", action="store_true"),
    ]
)
def update(args):
    """Update the source code in this project with the upstream HACL* code."""
    hacl_home = "../../hacl-star"  # this the default hacl home we use.
    if args.hacl_home:
        hacl_home = args.hacl_home
    if not os.path.isdir(hacl_home):
        print(
            "Unable to find %s.\nPlease provide the path to the root directory of your local copy of hacl-star."
            % hacl_home
        )
        exit(1)
    hacl_dist = join_path(hacl_home, "dist")
    src_path = "src"
    include_path = "include"
    """
    editions = [(name, new-code, target-src-dir, target-include-dir)]
    """
    editions = [
        ("std", join_path(hacl_dist, "gcc-compatible"), src_path, include_path),
        # #233 Don't update c89 for now.
        # (
        #     "c89",
        #     join_path(hacl_dist, "c89-compatible"),
        #     join_path(src_path, "c89"),
        #     join_path(include_path, "c89"),
        # ),
        (
            "msvc",
            join_path(hacl_dist, "msvc-compatible"),
            join_path(src_path, "msvc"),
            join_path(include_path, "msvc"),
        ),
    ]
    config_file = join_path("config", "config.json")
    files, file_names, includes, include_names = all_files(config_file, editions)
    update_hacl(files, includes, editions)

    # Update OCaml bindings
    def copy_ocaml_dir(directory):
        src = os.path.join(editions[0][1], directory)
        dest = os.path.join("ocaml", directory)
        shutil.copytree(src, dest)

    def copy_ocaml_file(file):
        src = os.path.join(editions[0][1], file)
        dest = os.path.join("ocaml", file)
        shutil.copyfile(src, dest)

    copy_ocaml_dir("lib")
    copy_ocaml_dir("lib_gen")
    copy_ocaml_file("ctypes.depend")

    update_karamel(hacl_dist)
    if not args.no_vale:
        update_vale(hacl_dist)

    # Update wasm files
    src = join_path(hacl_dist, "wasm")
    dest = join_path("src", "wasm")
    shutil.copytree(src, dest)
