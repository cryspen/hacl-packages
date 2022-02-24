# The Cryspen HACL Packages

![][status]

[HACL*] is a high-assurance cryptographic library developed as part of [Project Everest].
The HACL* repository includes source code written in [F*], generated code in C, verified assembly code
from the [Vale] project, and an agile multiplexed cryptographic provider called [EverCrypt].
As such, the full [HACL*] repository contains many software artifacts and a complicated build system
that can appear forbidding to a crypto developer who simply wishes to use verified crypto.

This repository addresses this gap by presenting several usable crypto packages developed by Cryspen on top of HACL*.
In particular, it contains a portable C crypto library that selects optimized implementations for each platform,
as well as Rust, OCaml, and JavaScript bindings for this library. Cryspen is in the process of adding more usable APIs for crypto
primitives, as well as extensive documentation for these APIs. Cryspen is also working on more optimized versions of some
algorithms.

[//]: # "links"
[hacl*]: https://hacl-star.github.io
[F*]: https://fstar-lang.org
[vale]: https://hacl-star.github.io/HaclValeEverCrypt.html
[evercrypt]: https://hacl-star.github.io/HaclValeEverCrypt.html
[status]: https://img.shields.io/badge/status-alpha-red.svg?style=for-the-badge
[Project Everest]: https://project-everest.github.io/