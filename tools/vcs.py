import glob
from os.path import isfile, join
from shutil import copytree
import subprocess
import os
from tempfile import mkdtemp
from tools.utils import argument, subcommand


def all_files(directory, extension):
    for f in os.listdir(directory):
        f = os.path.join(directory, f)
        if os.path.isfile(f) and f[-len(extension):] == extension:
            yield os.path.abspath(f)


@subcommand()
def update(args):
    """Update HACL* from upstream

    ⚠️  This will remove all local .c and .h files.
    """
    upstream_url = "https://github.com/project-everest/hacl-star.git"
    try:
        subprocess.run(['git', '--version'], check=True)
    except:
        print(" ⚠️  Please make sure that git is installed and in your path.")
        exit(1)

    # get absolute src and include directories
    my_dir = os.path.abspath(join(os.path.dirname(__file__), '..'))
    src_dir = join(my_dir, 'src')
    include_dir = join(my_dir, 'include')

    # clone hacl into a temp directory
    temp_hacl_dir = mkdtemp()
    subprocess.run(['git', 'clone', '--depth', '1',
                   upstream_url, temp_hacl_dir], check=True)
    new_dist = os.path.join(temp_hacl_dir, 'dist', 'gcc-compatible')

    # remove all .c and .h files from the src/include directory
    for f in all_files(src_dir, '.c'):
        os.remove(f)
    for f in all_files(include_dir, '.h'):
        os.remove(f)

    # copy new .c and .h files to the src/include directory
    def only_c(d, files): return [
        f for f in files if isfile(join(d, f)) and f[-2:] != '.c']
    copytree(new_dist, src_dir, ignore=only_c, dirs_exist_ok=True)

    def only_h(d, files): return [
        f for f in files if isfile(join(d, f)) and f[-2:] != '.h']
    copytree(new_dist, include_dir, ignore=only_h, dirs_exist_ok=True)

    print(" 💪  Copied all new .c and .h files from hacl-star.")
