#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import os
from os.path import join as path_join
import subprocess
import sys

from tools.utils import cmake_generated_config
from tools.utils import mprint as print
from ocaml.setup import copy_lib


def read_config():
    '''The make build requires environment variables from CMake.
    Read them here.
    '''
    with open(cmake_generated_config(), 'r') as f:
        cmake_config = f.readlines()
    environment = {**os.environ}
    for line in cmake_config:
        variable, value = line.split('=')
        if value == "TRUE":
            environment[variable] = "1"
    return environment


def build_ocaml():
    '''Build the OCaml bindings.
    '''
    # XXX: Windows is not supported
    if sys.platform == 'darwin':
        so = 'dylib'
    else:
        so = 'so'
    cwd = path_join(os.path.dirname(os.path.realpath(__file__)), '..')
    environment = {**os.environ,
                   "HACL_MAKE_CONFIG": path_join(cwd, "build", "cached-config.txt")}
    copy_lib(path_join(cwd, 'include'),
             path_join(cwd, 'vale', 'include'),
             path_join(cwd, 'build', 'Release'),
             path_join(cwd, 'karamel'),
             path_join(cwd, 'build'),
             "libhacl_static.a", "libhacl."+so, "config.h",
             path_join(cwd, 'ocaml', 'c'))
    make_cmd = 'make -C ocaml ocamlevercrypt.cmxa -j'
    subprocess.run(make_cmd, check=True, shell=True, env=environment)
    make_cmd = 'make -C ocaml -j'
    subprocess.run(make_cmd, check=True, shell=True, env=environment)


def test_ocaml():
    '''Test the OCaml bindings'''
    cwd = path_join(os.path.dirname(os.path.realpath(__file__)), '..')
    environment = {**os.environ,
                   "HACL_MAKE_CONFIG": path_join(cwd, "build", "cached-config.txt")}
    make_cmd = 'make -C ocaml test -j'
    subprocess.run(make_cmd, check=True, shell=True, env=environment)


def clean_ocaml():
    '''Clean the OCaml build.
    '''
    make_cmd = ['make', '-C', 'ocaml', 'clean']
    # This is noisy.
    subprocess.run(make_cmd, check=True, stdout=subprocess.DEVNULL)
