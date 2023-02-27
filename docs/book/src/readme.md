# Introduction

The Cryspen HACL packages is a collection of cryptographic libraries developed
by Cryspen on top of [HACL*].
In particular, it contains a portable [C crypto library] that selects optimized
implementations for each platform, as well as [Rust], [OCaml], and [JavaScript]
bindings for this library.

## Getting Started

If you want to build from sources or run tests, [get started on Github].

Depending on the language you are looking for there are different entry points.

- [C][c crypto library]
- [Rust]
- [OCaml]
- [JavaScript]

## Contributing

The Cryspen HACL packages are free and open source.
You can find the source code on [GitHub] and issues and feature requests can be
posted on the [GitHub issue tracker].
If you'd like to contribute, please read the [CONTRIBUTING] guide and
[developer section] and consider opening a [pull request].

---

The [HACL*] repository is a collection of high-assurance cryptographic
algorithms developed as part of [Project Everest].
It includes source code written in [F*], generated code in C, verified assembly
code from the [Vale] project, and an agile multiplexed cryptographic provider
called [EverCrypt].
As such, the full [HACL*] repository contains many software artifacts.

_[Get in touch] for more information or support._

[//]: # "links"
[cmake]: https://cmake.org/
[ninja]: https://ninja-build.org/
[mach]: ./mach
[gtest]: https://google.github.io/googletest/
[nlohmann_json]: https://github.com/nlohmann/json
[hacl*]: https://hacl-star.github.io
[f*]: https://fstar-lang.org
[vale]: https://hacl-star.github.io/HaclValeEverCrypt.html
[evercrypt]: https://hacl-star.github.io/HaclValeEverCrypt.html
[status]: https://img.shields.io/badge/status-alpha-red.svg?style=for-the-badge
[project everest]: https://project-everest.github.io/
[c crypto library]: ./hacl-c/
[rust]: ./hacl-rust/
[ocaml]: ./hacl-ocaml/
[javascript]: ./hacl-js/
[developer section]: ./developers/
[github]: https://github.com/cryspen/hacl-packages
[github issue tracker]: https://github.com/cryspen/hacl-packages/issues
[pull request]: https://github.com/cryspen/hacl-packages/pulls
[contributing]: https://github.com/cryspen/hacl-packages/blob/main/CONTRIBUTING.md
[get started on github]: https://github.com/cryspen/hacl-packages
[get in touch]: mailto:info@cryspen.com
