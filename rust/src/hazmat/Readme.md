# HACL API

This module contains the raw HACL API for use in other cryptographic libraries.

The functions don't perform any feature detection at runtime.
By default no optimized implementations are compiled.
They can be enabled with `--cfg simd128` and `--cfg simd256` at compile time.
