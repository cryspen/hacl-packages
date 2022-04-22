#!/usr/bin/env python3
#
#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT
#
# Setting up the HACL C library for the OCaml bindings.
# There are two different ways to do this
#
# ## mach build
# When working on the library, the preferred way to build the OCaml bindings is
# to use the top level mach script (`./mach build -l ocaml`).
# This uses the the local HACL C library.
#
# ## packaging
# For packaging the ocaml build needs to work "as is" without the super level
# C library.
# In this case this script pulls the HACL C library from the hacl-packages git
# repository and builds it locally.

import os
import pathlib
from os.path import join as path_join
import re
import shutil
import subprocess
import sys


def change_config(src_config, dst_config):
    '''Remove all comments from config.h so cppo can read it'''
    with open(src_config, "r") as src:
        lines = src.readlines()
    with open(dst_config, "w") as dst:
        for line in lines:
            dst.write(re.sub(r'(\/\/.*)|(\/\*.*\*\/)', '', line))


def copy_lib(include_path, vale_include_path, lib_path, karamel_path, config_path,
             static_lib, dynamic_lib, config_name, dest_path):
    '''Setup the C library to be usable by the bindings
    This expects the C library in lib_path and the includes in include_path.
    Note that we need to take all includes because the OCaml build doesn't
    respect library boundaries and uses internals.
    '''
    # Always remove whatever's in here.
    include_dst = path_join(dest_path, 'include')
    internal_include_dst = path_join(include_dst, "internal")
    shutil.rmtree(dest_path, ignore_errors=True)
    pathlib.Path(include_dst).mkdir(parents=True, exist_ok=True)
    pathlib.Path(internal_include_dst).mkdir(parents=True, exist_ok=True)

    # Get the include and lib.
    # Note that the library needs to be sitting here next to the Makefile
    includes = os.listdir(include_path)
    for file in includes:
        file = path_join(include_path, file)
        if os.path.isfile(file):
            shutil.copy(file, include_dst)
    vale_includes = os.listdir(vale_include_path)
    for file in vale_includes:
        file = path_join(vale_include_path, file)
        if os.path.isfile(file):
            shutil.copy(file, include_dst)
    internal_include_path = path_join(include_path, "internal")
    internal_includes = os.listdir(internal_include_path)
    for file in internal_includes:
        file = path_join(internal_include_path, file)
        if os.path.isfile(file):
            shutil.copy(file, internal_include_dst)
    shutil.copytree(karamel_path, path_join(dest_path, "kremlin"))
    cwd = os.path.dirname(os.path.realpath(__file__))
    shutil.copy(path_join(lib_path, static_lib), cwd)
    shutil.copy(path_join(lib_path, dynamic_lib), cwd)

    # Get the config.h, modify it, and put it into the include dir
    change_config(path_join(config_path, config_name),
                  path_join(include_dst, config_name))


def setup_pkg(static_lib, dynamic_lib, config_name, dest_path):
    '''Get the HACL C lib from the git repo for packaing'''
    shutil.rmtree('hacl-packages', ignore_errors=True)
    subprocess.run(
        ['git', 'clone', 'https://github.com/cryspen/hacl-packages', '--depth=1'],
        check=True)
    subprocess.run(
        ['./mach', 'build', '--release'],
        check=True, cwd='./hacl-packages')
    copy_lib(path_join('hacl-packages', 'include'),
             path_join('hacl-packages', 'vale', 'include'),
             path_join('hacl-packages', 'build', 'Release'),
             path_join('hacl-packages', 'kremlin'),
             path_join('hacl-packages', 'build'),
             static_lib, dynamic_lib,
             config_name, dest_path)


def main():
    # XXX: Windows is not supported
    if sys.platform == 'darwin':
        so = 'dylib'
    else:
        so = 'so'
    setup_pkg("libhacl_static.a", "libhacl."+so, "config.h", "./c/")


if __name__ == '__main__':
    main()
