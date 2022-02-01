import glob
import json
from os.path import isfile, join
from shutil import copytree, rmtree, copyfile
import subprocess
import os
from tempfile import mkdtemp
from tools.utils import argument, subcommand, mprint as print, json_config
from tools.configure import Config


def all_files(directory, extension):
    for f in os.listdir(directory):
        f = os.path.join(directory, f)
        if os.path.isfile(f) and f[-len(extension):] == extension:
            yield os.path.abspath(f)


@subcommand([argument("-p", "--path", help="Path to the new dist folder.", type=str)])
def update(args):
    """Update HACL* from upstream

    ⚠️  This will remove all local HACL files.
    The provided path must point to a directory with the same content as the `dist`
    folder in the HACL* F* repository.
    """
    print("🚧 Please use update.py for now ... 🚧")
    exit(1)
