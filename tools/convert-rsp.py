#!/usr/bin/env python3
#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 or MIT.
#    * http://www.apache.org/licenses/LICENSE-2.0
#    * http://opensource.org/licenses/MIT
#
# This simple script converts some .rsp files to JSON.

import json
import sys


def main():
    if len(sys.argv) != 3:
        print("Usage: ./convert-rsp.py <input-file> <output-file>")
        exit(1)
    input_file = sys.argv[1]
    print("Reading " + input_file)
    tests = []
    with open(input_file, "r") as input:
        lines = input.readlines()
        test = {}
        for line in lines:
            if line.startswith("Msg"):
                msg = line[6:-1]
                if msg == "00":
                    msg = ""
                test["msg"] = msg
            if line.startswith("MD"):
                test["md"] = line[5:-1]
                tests.append(test)
                test = {}
    output_file = sys.argv[2]
    print("Writing " + output_file)
    json_data = json.dumps(tests, indent=4)
    with open(output_file, "w") as output:
        output.write(json_data)


if __name__ == "__main__":
    main()
