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
