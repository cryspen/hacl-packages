import glob
from os.path import isfile, join
from shutil import copytree
import subprocess
import os
from tempfile import mkdtemp
from tools.utils import argument, subcommand, mprint as print


def all_files(directory, extension):
    for f in os.listdir(directory):
        f = os.path.join(directory, f)
        if os.path.isfile(f) and f[-len(extension):] == extension:
            yield os.path.abspath(f)


@subcommand()
def update(args):
    """Update HACL* from upstream

    ⚠️  This will remove all local HACL files.
    Note that this will not update Vale files. Vale has to be updated manually.
    """
    upstream_url = "https://github.com/project-everest/hacl-star.git"
    try:
        subprocess.run(['git', '--version'], check=True)
    except:
        print("⚠️  Please make sure that git is installed and in your path.")
        exit(1)
    print(" ⚠️  This will remove all local HACL files.")
    really = input(" > Continue? [y/N] ")
    if not really.lower() in ["y", "yes"]:
        print(" 💡 Aborting update.")
        exit(1)

    # get absolute src and include directories
    my_dir = os.path.abspath(join(os.path.dirname(__file__), '..'))

    # clone hacl into a temp directory
    temp_hacl_dir = mkdtemp()
    subprocess.run(['git', 'clone', '--depth', '1',
                   upstream_url, temp_hacl_dir], check=True)

    # TODO: #12 Only copy files that we want
    def copy_files(new_dist, src_dir, include_dir):
        # remove all .c and .h files from the src/include directory
        for f in all_files(src_dir, '.c'):
            os.remove(f)
        for f in all_files(include_dir, '.h'):
            os.remove(f)

        # copy new .c and .h files to the src/include directory
        def only_c(d, files):
            files = [f for f in files if isfile(
                join(d, f)) and f[-2:] != '.c' or "vale" in f.lower()]
            return files
        copytree(new_dist, src_dir, ignore=only_c, dirs_exist_ok=True)

        def only_h(d, files):
            files = [f for f in files if isfile(
                join(d, f)) and f[-2:] != '.h' or "vale" in f.lower()]
            return files
        copytree(new_dist, include_dir, ignore=only_h, dirs_exist_ok=True)

    src_dir = join(my_dir, 'src')
    include_dir = join(my_dir, 'include')
    new_dist = os.path.join(temp_hacl_dir, 'dist', 'gcc-compatible')
    copy_files(new_dist, src_dir, include_dir)

    src_dir = join(src_dir, 'c89')
    include_dir = join(include_dir, 'c89')
    c89_dist = os.path.join(temp_hacl_dir, 'dist', 'c89-compatible')
    copy_files(c89_dist, src_dir, include_dir)

    src_dir = join(my_dir, 'src', 'msvc')
    include_dir = join(my_dir, 'include', 'msvc')
    msvc_dist = os.path.join(temp_hacl_dir, 'dist', 'msvc-compatible')
    copy_files(msvc_dist, src_dir, include_dir)

    print(" [mach] 💪  Copied all new .c and .h files from hacl-star.")
