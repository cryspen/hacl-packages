# Contributing to HACL Packages

## Code Style

Handwritten C and CPP code is formatted with the Mozilla clang-format style.

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
This may lead to broken links when reading the documentation locally.
Try to remove the `main` path from the URL if you experience this problem.
