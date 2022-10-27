#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import os
import shutil
import subprocess

from tools.utils import argument, check_cmd, mprint as print, subcommand


@subcommand(
    [
        argument(
            "--ocaml",
            help="Build OCaml docs as well (requires dune).",
            action="store_true",
        )
    ]
)
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

    os.makedirs("build", exist_ok=True)

    print("# Building book")
    backup = os.getcwd()
    os.chdir("docs/book")
    subprocess.call(["mdbook", "build", "--dest-dir", "../../build/docs"])
    os.chdir(backup)

    print("# Building C API Reference")
    os.makedirs("build/docs/c/main", exist_ok=True)
    subprocess.call(["sphinx-build", "docs/reference", "build/docs/c/main"])

    if args.ocaml:
        check_cmd("dune", "--version")
        print("# Building OCaml API Reference")
        os.makedirs("build/docs/ocaml/main", exist_ok=True)
        subprocess.call(["sh", "opam.sh"])
        os.chdir("opam")
        subprocess.call(["dune", "build", "@doc", "--only-packages=hacl-star"])
        os.chdir(backup)
        shutil.copytree(
            "opam/_build/default/_doc/_html",
            "build/docs/ocaml/main",
            dirs_exist_ok=True,
        )

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
    print("    build/docs/c/main/index.html")
    print("")
