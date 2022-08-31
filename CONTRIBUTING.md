# Contributing to HACL Packages

## Code Style

Handwritten C and CPP code is formatted with the Mozilla clang-format style.

## Documentation

* Due to the use of sphinx-multiversion, you must make sure that all changes have been commited before regenerating the documentation. Otherwise you won't see your changes. (This may be improved in the future.)
* All examples are written as unit tests in the `tests` folder and included in the documentation with, e.g., ...

	```{literalinclude} ../../../../tests/sha2.cc
	:language: C
	:dedent:
	:start-after: "// START OneShot"
	:end-before: "// END OneShot"
	```
* sphinx-multiversion generates multiple versions of the documentation.
