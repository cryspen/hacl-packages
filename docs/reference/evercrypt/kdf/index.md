# KDF

EverCrypt's Key Derivation Functions (KDFs).

Key derivation functions (KDFs) are used to derive cryptographically strong keys from an initial secret value.

## HKDF

HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869].

Similar to [RFC 5869], the following descriptions uses the term `HashLen` to denote the output length of the hash function of a concrete instantiation of HKDF.

The following instantiations are supported:

* BLAKE2b (`HashLen` = 64)
* BLAKE2s (`HashLen` = 32)
* SHA2-256 (`HashLen` = 32)
* SHA2-512 (`HashLen` = 64)
* SHA1 (`HashLen` = 20)

### API Reference

```{doxygenfunction} EverCrypt_HKDF_extract
```

```{doxygenfunction} EverCrypt_HKDF_expand
```

[rfc 5869]: https://www.rfc-editor.org/rfc/rfc5869
