# HACL Rust bindings

![Maturity Level][maturity-badge]
[![Build & Test][github-actions-badge]][github-actions-link]
[![ARM Build][drone-badge]][drone-link]

This is the `hacl-rust` crate that provides Rust bindings for the HACL C package.
The FFI bindings are in the [hacl-rust-sys](hacl-rust-sys/) crates.

**⚠️ Note:** This crate is still work in progress.
Don't use in production just yet.

| Platform    | Supported |
| :---------- | :-------: |
| MacOS       |    ✅     |
| MacOS Arm64 |    ✅     |
| iOS         |    ✅     |
| Linux x64   |    ✅     |
| Linux x86   |    ✅     |
| Windows x64 |    ✅     |
| Arm64 Linux |    ✅     |
| Arm32 Linux |    ✅     |

## Crates

| Name          | Crates.io                                                                         |                                               Docs                                               |
| :------------ | :-------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------: |
| hacl-rust-sys | [![crates.io][hacl-rust-sys-crate-badge]](https://crates.io/crates/hacl-rust-sys) | [![Docs][docs-main-badge]](https://tech.cryspen.com/hacl-packages/rust/hacl-rust-sys/index.html) |
| hacl-rust     | [![crates.io][hacl-rust-crate-badge]](https://crates.io/crates/hacl-rust)         |   [![Docs][docs-main-badge]](https://tech.cryspen.com/hacl-packages/rust/hacl-rust/index.html)   |

## Features

By default the hacl-rust crate includes the `random` feature that allows generating random values (keys, nonces, etc.).
But this is not verified code and uses the [rand](https://crates.io/crates/rand) crate. It can be disabled with `--no-default-features`.
Please bring your own randomness if you want to be safe.

## Platforms

See above for a list of supported platforms.

### Building

Please see the [top level readme] for how to build.

## Benchmarks

To run benchmarks use `cargo bench`.

## Tests

All primitives are tested against the [Wycheproof](https://github.com/google/wycheproof) test vectors.
They can be run with `cargo test`.
This will also run automatically generated binding tests from bindgen.

[maturity-badge]: https://img.shields.io/badge/maturity-beta-orange.svg?style=for-the-badge
[github-actions-badge]: https://img.shields.io/github/workflow/status/franziskuskiefer/evercrypt-rust/Build%20&%20Test?label=build%20%26%20tests&logo=github&style=for-the-badge
[github-actions-link]: https://github.com/franziskuskiefer/evercrypt-rust/actions/workflows/hacl-rust.yml?query=branch%3Amain
[drone-badge]: https://img.shields.io/drone/build/franziskuskiefer/evercrypt-rust?label=ARM%20BUILD&style=for-the-badge
[drone-link]: https://cloud.drone.io/franziskuskiefer/evercrypt-rust
[evercrypt-crate-badge]: https://img.shields.io/crates/v/hacl-rust-sys.svg?style=for-the-badge
[hacl-rust-sys-crate-badge]: https://img.shields.io/crates/v/evercrypt.svg?style=for-the-badge
[docs-main-badge]: https://img.shields.io/badge/docs-main-blue.svg?style=for-the-badge
[top level readme]: https://github.com/cryspen/hacl-packages#readme
