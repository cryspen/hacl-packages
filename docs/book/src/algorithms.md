# Algorithms

The following tables gives an overview over the algorithms supported by the HACL
packages.

For a detailed description fo the Support column, please see the [Architectures section](./architectures.md).

| Family               | Algorithm         | Support                                 |
| -------------------- | ----------------- | --------------------------------------- |
| AEAD                 | AES-GCM 128       | AES-NI & CLMUL (x86 only)               |
| AEAD                 | AES-GCM 256       | AES-NI & CLMUL (x86 only)               |
| AEAD                 | Chacha20-Poly1305 | Portable \| vec128 \| vec256            |
| ECDH                 | Curve25519        | Portable \| BMI2 & ADX                  |
| ECDH                 | P-256             | Portable                                |
| Signature            | Ed25519           | Portable                                |
| Signature            | ECDSA P-256r1     | Portable                                |
| Signature            | ECDSA P-256k1     | Portable                                |
| Signature            | RSA-PSS           | Portable                                |
| Hash                 | SHA2-224          | Portable \| SHAEXT                      |
| Hash                 | SHA2-256          | Portable \| SHAEXT                      |
| Hash                 | SHA2-384          | Portable                                |
| Hash                 | SHA2-512          | Portable                                |
| Hash                 | SHA3              | Portable                                |
| Hash                 | Blake2            | Portable \| vec128 \| vec256            |
| Key Derivation       | HKDF              | Portable (depends on hash)              |
| Symmetric Encryption | Chacha20          | Portable \| vec128 \| vec256            |
| Symmetric Encryption | Salsa20           | Portable                                |
| Symmetric Encryption | AES 128           | AES-NI & CLMUL (x86 only)               |
| Symmetric Encryption | AES 256           | AES-NI & CLMUL (x86 only)               |
| MAC                  | HMAC              | Portable (depends on hash)              |
| MAC                  | Poly1305          | Portable \| vec128 \| vec256 \| x64 ASM |
| Hybrid Encryption    | Nacl              | Portable                                |
| Hybrid Encryption    | HPKE              | Portable (depends on hash, aead, dh)    |
| Random Generation    | HMAC-DRBG         | Portable (depends on hash)              |
