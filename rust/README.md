# HACL Rust bindings

[![Build & Test][github-actions-badge]][github-actions-link]
[![crates.io][hacl-crate-badge]](https://crates.io/crates/hacl)
[![Docs][docs-badge]](https://docs.rs/hacl)

This is the `hacl` crate that provides Rust bindings for the HACL C package.
The FFI bindings are in the [hacl-sys](hacl-sys/) crates.

Please see the [top level readme] for more information about the underlying code.

| Platform    | Supported |
| :---------- | :-------: |
| MacOS       |    ✅     |
| MacOS Arm64 |    ✅     |
| iOS         |    ✅     |
| Linux x64   |    ✅     |
| Linux x86   |    ✅     |
| Windows x64 |    ✅     |
| Windows x86 |    ✅     |
| Arm64 Linux |    ✅     |
| Arm32 Linux |    ✅     |

## Features

By default the hacl crate includes the `random` feature that allows generating random values (keys, nonces, etc.).
But this is not verified code and uses the [rand](https://crates.io/crates/rand) crate. It can be disabled with `--no-default-features`.
Please bring your own randomness if you want to be safe.

## Platforms

See above for a list of supported platforms.

### Building

```bash
cargo build
```

## Benchmarks

To run benchmarks use `cargo bench`.

## Tests

All primitives are tested against the [Wycheproof](https://github.com/google/wycheproof) test vectors.
They can be run with `cargo test`.
This will also run automatically generated binding tests from bindgen.

[maturity-badge]: https://img.shields.io/badge/maturity-beta-orange.svg?style=for-the-badge
[github-actions-badge]: https://img.shields.io/github/actions/workflow/status/cryspen/hacl-packages/rust.yml?label=build%20%26%20tests&logo=github&style=for-the-badge&branch=main
[github-actions-link]: https://github.com/cryspen/hacl-packages/actions/workflows/rust.yml?query=branch%3Amain
[hacl-crate-badge]: https://img.shields.io/crates/v/hacl.svg?style=for-the-badge
[docs-badge]: https://img.shields.io/badge/docs-blue.svg?style=for-the-badge
[top level readme]: https://github.com/cryspen/hacl-packages#readme
