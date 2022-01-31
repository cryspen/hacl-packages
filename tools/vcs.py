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
    hacl_dist_dir = args.path
    if hacl_dist_dir is None:
        print(" ⚠️  Please provide a path with the new distribution using --path or -p.")
        exit(1)
    hacl_dist_dir = os.path.abspath(
        join(os.path.dirname(__file__), '..', hacl_dist_dir))
    print(" ⚠️  This will override all local changes!")
    really = input(" > Continue? [y/N] ")
    if not really.lower() in ["y", "yes"]:
        print(" 💡  Aborting update.")
        exit(1)

    # get absolute src and include directories
    my_dir = os.path.abspath(join(os.path.dirname(__file__), '..'))

    # TODO: #13 Copy tests from upstream
    def copy_files(new_dist, src_dir, include_dir, config):
        # First remove src and include folders.
        rmtree(src_dir, ignore_errors=True)
        os.mkdir(src_dir)
        rmtree(include_dir, ignore_errors=True)
        os.mkdir(include_dir)

        for source in config["sources"]:
            file_name = os.path.basename(source)
            src = join(new_dist, file_name)
            dest = join(src_dir, file_name)
            copyfile(src, dest)

        for include in config["includes"]:
            file_name = os.path.basename(include)
            src = join(new_dist, os.path.basename(file_name))
            dest = join(include_dir, file_name)
            copyfile(src, dest)

        copytree(join(new_dist, "internal"), join(src_dir, "internal"))

    # # read dependency config file
    # # XXX: re-generate first?
    # with open(dep_config(), 'r') as f:
    #     data = f.read()

    # # parse file
    # config = json.loads(data)

    # Configure
    source_dir = "src"
    include_dir = "include"
    config = Config(json_config(), source_dir, include_dir)
    config = config.dep_config()

    sources = []
    for feature in config["sources"]:
        sources.extend(config["sources"][feature])
    config["sources"] = sources
    vale_sources = []
    for platform in config["vale_sources"]:
        vale_sources.extend(config["vale_sources"][platform])
    config["vale_sources"] = vale_sources

    src_dir = join(my_dir, 'src')
    include_dir = join(my_dir, 'include')
    new_dist = os.path.join(hacl_dist_dir, 'gcc-compatible')
    copy_files(new_dist, src_dir, include_dir, config)

    src_dir = join(src_dir, 'c89')
    include_dir = join(include_dir, 'c89')
    c89_dist = os.path.join(hacl_dist_dir, 'c89-compatible')
    config = Config(json_config(), source_dir, include_dir)
    config = config.dep_config()
    # "copy"
    # for source in sources:
    #     file_name = os.path.basename(source)
    #     src = join(c89_dist, file_name)
    #     dest = join(my_dir, "src", "c89", file_name)
    #     print("%s -> %s" % (src, dest))
    copy_files(c89_dist, src_dir, include_dir, config)

    src_dir = join(my_dir, 'src', 'msvc')
    include_dir = join(my_dir, 'include', 'msvc')
    msvc_dist = os.path.join(hacl_dist_dir, 'msvc-compatible')
    config = Config(json_config(), source_dir, include_dir)
    config = config.dep_config()
    copy_files(msvc_dist, src_dir, include_dir, config)

    print(" [mach] 💪  Copied all new .c and .h files from %s." %
          (hacl_dist_dir))
