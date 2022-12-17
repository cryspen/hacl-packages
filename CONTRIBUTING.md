# Contributing to HACL Packages

## Code Style

Handwritten C and CPP code is formatted with the Mozilla clang-format style.

## Benchmarking

Benchmarks are run with

```bash
./mach build --benchmark --release
```

This includes comparison with OpenSSL and therefore requires OpenSSL 3 to be
available.
If OpenSSL is not in the default path the environment variable `OPENSSL_HOME`
can be set.
To disable OpenSSL benchmarks `--no-openssl` can be added to the command.

## Documentation

The `mach` script tries to detect the required dependencies.
However, this is currently not done for `pip` packages.
The packages required to build the C API reference via sphinx are listed in `docs/reference/requirements.txt`.

You can install them via ...

```sh
pip install -r docs/reference/requirements.txt
```

You can then run ...

```sh
./mach doc
```

... to generate HACL Packages' documentation.

All examples should be written as unit tests in the `tests` folder and can be included in the documentation with ...

	```{literalinclude} ../../../../tests/sha2.cc
	:language: C
	:dedent:
	:start-after: "// START OneShot"
	:end-before: "// END OneShot"
	```
In CI, we use sphinx-multiversion to generate multiple versions of the documentation.

## Updating from upstream
The C code in this repository is generated from [hacl-star/hacl-star] (or [the
Cryspen fork]).

```sh
./mach update -s <hacl-star-root>
```

Follow the checklist below to finish the update
- add new files that are needed to
  - git
  - `config.json`
- make sure the c89 folders are not changed (also see #233)
- remove unused files with `git clean -f`
- re-create config `./mach build -c --no-build`
- update default config `cp build/config.cmake config/default_config.cmake`

When #12 is fully implemented most of these manual steps should not be needed anymore.

[hacl-star/hacl-star]: https://github.com/hacl-star/hacl-star
[the Cryspen fork]: https://github.com/cryspen/hacl-star
