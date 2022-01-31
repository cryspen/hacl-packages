---
title: The High Assurance Crypto Library
---

# The High Assurance Crypto Library

The High Assurance Crypto Library (HACL) is based on [HACL*], [Vale], and
[Evercrypt].
It is a low-level library that implements the most commonly used cryptographic
primitives.

## Supported Algorithms

### AEAD

- AES-GCM 128 and 256
- Chacha20Poly1305

See {ref}`AEAD_Usage` for how to use AEADs.

### Signatures

- Ed25119
- EcDSA P256 SHA2-256
- RSA-PSS

### Hashing

- SHA2-224
- SHA2-256
- SHA2-384
- SHA2-512
- SHA3
  - TODO
- Blake2
  - Blake2b
  - Blake2s

### Key Derivation

- HKDF
- SHA3

### Message Authentication (MAC or keyed hashes)

- HMAC
- Blake2 keyed

### (Elliptic-Curve) Diffie Hellmann

- P-256
- x25519

### Permutations

- Chacha
- AES
- Shake

[//]: # "links"
[hacl*]: https://hacl-star.github.io
[vale]: https://hacl-star.github.io/HaclValeEverCrypt.html
[evercrypt]: https://hacl-star.github.io/HaclValeEverCrypt.html

```{toctree}
:maxdepth: 2
:caption: Contents

bindings
build
developer
platforms
usage/aead
```
