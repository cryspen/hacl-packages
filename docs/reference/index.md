# Welcome to HACL Packages' documentation!

HACL Packages provides ready-to-use crypto algorithms based on the formally verified code from the [HACL\* repository].

This manual describes the HACL\* and EverCrypt C APIs. The HACL\* API provides a lightweight and direct interface to all supported algorithms and their different implementations. To use the most efficient implementation, you must be aware of the platform you intend to run HACL\* on.

EverCrypt, on the other hand, is a cryptographic *provider*. The EverCrypt API provides a unified interface to all supported algorithms. It always selects the most efficient implementation that is available at runtime.

```{toctree}
:maxdepth: 2
:caption: "Contents:"

hacl/index
evercrypt/index
```

[HACL\* repository]: https://github.com/hacl-star/hacl-star
