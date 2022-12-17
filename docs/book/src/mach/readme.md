# mach

The main entry point for all operations is the `mach` script.

## Dependencies

Building HACL from sources requires a set of basic dependencies

- cmake > 3.17
- ninja
- python > 3.8
- clang or gcc (note that primarily clang is used)

## Command line reference

```
usage: mach [-h] {test,install,build,clean} ...

positional arguments:
  {test,install,build,clean}

optional arguments:
  -h, --help            show this help message and exit
```
