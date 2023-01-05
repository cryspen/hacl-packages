#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import os
import subprocess
import sys
import shutil
from os.path import join as path_join
from os.path import exists as path_exists


def build_js():
    """Build the JS bindings."""

    cwd = path_join(os.path.dirname(os.path.realpath(__file__)), "..")
    src_path = path_join(cwd, "src", "wasm")
    bindings_path = path_join(cwd, "js")
    dest_path = path_join(cwd, "build", "js")

    shutil.rmtree(dest_path, ignore_errors=True)
    shutil.copytree(src_path, dest_path)
    shutil.copytree(bindings_path, dest_path, dirs_exist_ok=True)


def test_js():
    """Test the JS bindings."""

    cwd = path_join(os.path.dirname(os.path.realpath(__file__)), "..")
    path = path_join(cwd, "build", "js")

    if not path_exists(path):
        print(
            "! Build missing! Please build js bindings first: `./mach build -l js`. Aborting!"
        )
        exit(1)

    os.chdir(path)

    test1_cmd = ["node", "api_test.js"]
    test2_cmd = ["node", "test2.js"]
    test3_cmd = ["node", "test3.js"]

    subprocess.run(test1_cmd, check=True)
    subprocess.run(test2_cmd, check=True)
    subprocess.run(test3_cmd, check=True)
