# Try detecting the location of openssl.

import subprocess
from tools.utils import mprint


def find_openssl_home():
    # OPENSSL_ROOT=$(shell which brew >/dev/null && brew info --quiet openssl | egrep '^/' | cut -f 1 -d ' ')
    mprint(f"Probing for openssl with brew ... ")
    try:
        result = subprocess.run(
            ["brew info --quiet openssl | egrep '^/' | cut -f 1 -d ' ' | tail -n 1"], shell=True, capture_output=True, text=True
        ).stdout.rstrip()
        mprint("Found OpenSSL at", result)
        return result
    except:
        mprint("Unable to find brew or openssl")
        mprint(
            f'Please set the OPENSSL_HOME environment variable to OpenSSL 3 manually.')
        return None
