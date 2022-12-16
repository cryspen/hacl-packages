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


def build_js():
    """Build the JS bindings."""

    cwd = path_join(os.path.dirname(os.path.realpath(__file__)), "..")
    src_path = path_join(cwd, "src/wasm")
    bindings_path = path_join(cwd, "js")
    dest_path = path_join(cwd, "build/js")

    shutil.rmtree(dest_path, ignore_errors=True)
    shutil.copytree(src_path, dest_path)
    shutil.copytree(bindings_path, dest_path, dirs_exist_ok=True)

    os.chdir(dest_path)
    test_cmd = ["node", "api_test.js"]
    subprocess.run(test_cmd, check=True)
