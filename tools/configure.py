import os
import json
import re
import subprocess
from os.path import join


class Config:

    def dependencies(self, algorithm, source_file):
        """Collect dependencies for a given c file

        Use `clang -MM` to collect dependencies for a given c file assuming header
        and source files are named the same.
        """
        # We only get dependencies for files that don't require features.
        # Any feature file will require a top level file.
        if source_file["features"] != "std":
            return join("src", source_file["file"])
        source_file = source_file["file"]
        # Build dependency graph
        result = subprocess.run(
            'clang -I include -I build -I kremlin/include/ -I kremlin/kremlib/dist/minimal -MM src/'+source_file,
            stdout=subprocess.PIPE,
            shell=True,
            check=True)
        stdout = result.stdout.decode('utf-8')

        files = []
        for line in stdout.splitlines():
            # Remove object file and the c file itself
            line = re.sub("(\w*).o: src/(\w*).c", "", line)
            line = line.strip()
            line = line.split(' ')
            try:
                line.remove("\\")
            except:
                # This is fine
                pass
            files.extend(line)

        # Get all source files in src/
        # FIXME: Does this work on Windows?
        result = subprocess.run(
            'ls -1a src/*.c', stdout=subprocess.PIPE, shell=True)
        source_files = result.stdout.decode('utf-8')
        source_files = source_files.splitlines()
        # remove src/ and .c
        source_files = list(map(lambda s: s[4:-2], source_files))

        # Now let's collect the c files from the included headers
        # This adds all files without looking at the feature requirements into deps.
        deps = []
        for include in files:
            # Get the file name from the path (could be done more efficiently before)
            include_match = re.match(
                "^(.*/)?(?:$|(.+?)(?:(\.[^.]*$)|$))", include)
            include = include_match.group(2)
            # Only add the dependency if there's a corresponding source file.
            if include in source_files:
                deps.append(join("src", include+".c"))
        return deps

    def __init__(self, config_file, algorithms=[]):
        """Read the build config from the json file"""
        print(" [mach] Using %s to configure ..." % (config_file))

        # read file
        with open(config_file, 'r') as f:
            data = f.read()

        # parse file
        self.config = json.loads(data)
        self.kremlin_files = self.config["kremlin_sources"]
        self.kremlin_include_paths = self.config["kremlin_include_paths"]
        self.include_paths = self.config["include_paths"]
        self.hacl_files = self.config["hacl_sources"]
        self.evercrypt_files = self.config["evercrypt_sources"]
        self.tests = self.config["tests"]

        # Filter algorithms in hacl_files
        # In the default case (empty list of algorithms) we don't do anything.
        if len(algorithms) != 0:
            # Check if the algorithms are actually valid
            for alg in algorithms:
                if not alg in self.hacl_files:
                    print(" [mach] ⚠️  Unsupported algorithm requested: %s" % alg)
                    exit(1)
            for a, _ in list(self.hacl_files.items()):
                if not a in algorithms:
                    del self.hacl_files[a]
            for a, _ in list(self.evercrypt_files.items()):
                if not a in algorithms:
                    del self.evercrypt_files[a]
            for a, _ in list(self.tests.items()):
                if not a in algorithms:
                    del self.tests[a]

        # Collect dependencies for the hacl files.
        self.hacl_compile_files = {}
        self.hacl_compile_feature = {}
        all_feature_files = []  # Only a helper to filer hacl_compile_files
        for a in self.hacl_files:
            for source_file in self.hacl_files[a]:
                files = self.dependencies(a, source_file)
                if a in self.hacl_compile_files:
                    self.hacl_compile_files[a].extend(
                        files if type(files) == list else [files])
                else:
                    # Add the new algorithm dependency
                    self.hacl_compile_files[a] = files
                feature = source_file["features"]
                if feature != "std":
                    # Collect all files requiring features to filter std sources later
                    all_feature_files.extend(
                        files if type(files) == list else [files])
                if feature in self.hacl_compile_feature:
                    self.hacl_compile_feature[feature].extend(
                        files if type(files) == list else [files])
                else:
                    # Add the new feature dependency
                    self.hacl_compile_feature[feature] = files if type(files) == list else [
                        files]
        # Remove files that require additional features from hacl_compile_files
        # print(self.hacl_compile_feature["std"])
        self.hacl_compile_feature["std"] = [
            file for file in self.hacl_compile_feature["std"] if file not in all_feature_files]
        # for file in self.hacl_compile_feature["std"]:
        #     print(file)
        #     if file in all_feature_files:
        #         self.hacl_compile_feature["std"].remove(file)
        # print(all_feature_files)
        # print(self.hacl_compile_feature["std"])
        # exit(1)

        # Set kremlin as include paths
        self.include_paths.extend(self.kremlin_include_paths)

        # Flatten test sources
        self.test_sources = [f for files in [self.tests[b]
                                             for b in self.tests] for f in files]

        # TODO: evercrypt dependencies and features.
        # self.evercrypt_compile_files = {}
        # for a in self.evercrypt_files:
        #     for source_file in self.evercrypt_files[a]:
        #         self.evercrypt_compile_files[a] = self.dependencies(
        #             a, source_file)

        # Remove duplicates from all lists
        for k in self.hacl_compile_files:
            self.hacl_compile_files[k] = list(
                dict.fromkeys(self.hacl_compile_files[k]))
        for k in self.hacl_compile_feature:
            self.hacl_compile_feature[k] = list(
                dict.fromkeys(self.hacl_compile_feature[k]))

    def write_cmake_config(self, cmake_config):
        print(" [mach] Writing cmake config to %s ..." % (cmake_config))
        print(" [mach] THIS OVERRIDES %s. (But it's too late now ... )" %
              cmake_config)
        with open(cmake_config, 'w') as out:
            if len(self.kremlin_files) > 0:
                out.write("set(KREMLIN_FILES %s)\n" %
                          " ".join(f for f in self.kremlin_files))

            for a in self.hacl_compile_feature:
                out.write("set(SOURCES_%s %s)\n" %
                          (a, " ".join(join("${PROJECT_SOURCE_DIR}", f) for f in self.hacl_compile_feature[a])))

            out.write("set(ALGORITHMS %s)\n" %
                      " ".join(a for a in self.hacl_files))

            out.write("set(INCLUDE_PATHS %s)\n" %
                      " ".join(join("${PROJECT_SOURCE_DIR}", p) for p in self.include_paths))

            out.write("set(TEST_SOURCES %s)\n" %
                      (" ".join(join("${PROJECT_SOURCE_DIR}", "tests", f) for f in self.test_sources)))
            # # for a in hacl_files:
            # #     out.write("option(%s \"\" ON)\n" % a)
            # out.write("set(ALGORITHM_HACL_FILES %s)\n" %
            #           " ".join("HACL_FILES_"+a for a in self.hacl_files))

            # for a in self.hacl_compile_files:
            #     out.write("set(HACL_FILES_%s %s)\n" %
            #               (a, " ".join("${PROJECT_SOURCE_DIR}/"+f for f in self.hacl_compile_files[a])))

            # out.write("set(ALGORITHM_EVERCRYPT_FILES %s)\n" %
            #           " ".join("EVERCRYPT_FILES_"+a for a in self.evercrypt_files))
            # for a in self.evercrypt_files:
            #     out.write("set(EVERCRYPT_FILES_%s %s)\n" %
            #               (a, " ".join("${PROJECT_SOURCE_DIR}/"+f for f in self.evercrypt_files[a])))

            # for f in self.features:
            #     out.write("set(REQUIRED_FEATURES_%s %s)\n" % (os.path.splitext(
            #         f)[0], " ".join(feature for feature in self.features[f])))

            # for f in self.cpu_features:
            #     out.write("set(CPU_FEATURE_%s %s)\n" % (os.path.splitext(
            #         f)[0], " ".join("${PROJECT_SOURCE_DIR}/src/"+file for file in self.cpu_features[f])))

            out.write("set(ALGORITHM_TEST_FILES %s)\n" %
                      " ".join("TEST_FILES_"+a for a in self.tests))
            for a in self.tests:
                out.write("set(TEST_FILES_%s %s)\n" %
                          (a, " ".join(f for f in self.tests[a])))

    def source_files(self):
        """Get a list of all source files in the config."""
        out = []
        for a in self.hacl_compile_files:
            out.extend(self.hacl_compile_files[a])
        for a in self.evercrypt_compile_files:
            out.extend(self.evercrypt_compile_files[a])
        return out

    # TODO: we first have to create a list of headers
    def header_files(self):
        """Get a list of all header files in the config."""
        pass
