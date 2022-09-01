#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT

import subprocess

# Helper functions for macOS.


def ios_sysroot():
    """Returns the sysroot of the iOS SDK"""
    result = subprocess.run(
        "xcrun --sdk iphoneos --show-sdk-path",
        stdout=subprocess.PIPE,
        shell=True,
        check=True,
    )
    return result.stdout.decode("utf-8")[:-1]


def aarch64_ios_args():
    """Returns clang arguments to build for aarch64 iOS"""
    return ["-isysroot", ios_sysroot()]
