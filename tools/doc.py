#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import os
import subprocess

from tools.utils import check_cmd, mprint as print, subcommand


@subcommand([])
def doc(args):
    """Build the HACL Packages documentation"""

    check_cmd("mdbook", "help")
    check_cmd("doxygen", "--version")
    check_cmd("sphinx-build", "--help")
    print("")
    print("Please also install all required sphinx dependencies by executing ...")
    print("")
    print("    pip install -r docs/reference/requirements.txt")
    print("")

    if not os.path.exists("build"):
        os.mkdir("build")

    print("# Building book")
    backup = os.getcwd()
    os.chdir("docs/book")
    subprocess.call(["mdbook", "build", "--dest-dir", "../../build/docs"])
    os.chdir(backup)

    print("Building C API Reference")
    subprocess.call(["sphinx-build", "docs/reference", "build/docs/c"])

    print("Finished.")
    print("")
    print("You can view the book by opening ...")
    print("")
    print("    build/docs/index.html")
    print("")
    print("... in a browser.")
    print("")
    print("The C API Reference is available at ...")
    print("")
    print("    build/docs/c/index.html")
    print("")
