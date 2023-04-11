# hacl-sys

[![Build & Test][github-actions-badge]][github-actions-link]
![Rust Version][rustc-image]
[![crates.io][hacl-sys-crate-badge]](https://crates.io/crates/hacl-sys)
[![Docs][docs-badge]](https://docs.rs/hacl-sys)

Rust wrapper for [hacl](https://github.com/cryspen/hacl-packages).

### Platforms

| Platform             | Supported |
| :------------------- | :-------: |
| MacOS                |    ✅     |
| MacOS Arm64          |    ✅     |
| iOS                  |    ✅     |
| iOS Simulator x86_64 |    ❌     |
| Linux x64            |    ✅     |
| Linux x86            |    ✅     |
| Windows x64          |    ❌     |
| Arm64 Linux          |    ✅     |
| Arm32 Linux          |    ✅     |

#### Building on Windows

Enabling builds on Windows is tracked in [#78](https://github.com/cryspen/hacl-packages/issues/78).

<!-- To build `evercrypt` and `evercrypt-sys` on Windows ensure path for the `VsDevCmd.bat`
called in in `hacl-build.bat` is correct on your system.
The build has only been tested with VisualStudio 2019. -->

[maturity-badge]: https://img.shields.io/badge/maturity-beta-orange.svg?style=for-the-badge
[github-actions-badge]: https://img.shields.io/github/actions/workflow/status/cryspen/hacl-packages/rust.yml?label=build%20%26%20tests&logo=github&style=for-the-badge&branch=main
[github-actions-link]: https://github.com/cryspen/hacl-packages/actions/workflows/rust.yml?query=branch%3Amain
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg?style=for-the-badge
[docs-badge]: https://img.shields.io/badge/docs-blue.svg?style=for-the-badge
[hacl-sys-crate-badge]: https://img.shields.io/crates/v/hacl-sys.svg?style=for-the-badge
