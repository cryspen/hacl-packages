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

Extract a fixed-length pseudorandom key from input keying material.

* `a` Hash function to use. The allowed values are:
  * `Spec_Hash_Definitions_Blake2B`, 
  * `Spec_Hash_Definitions_Blake2S`, 
  * `Spec_Hash_Definitions_SHA2_256`, 
  * `Spec_Hash_Definitions_SHA2_384`, 
  * `Spec_Hash_Definitions_SHA2_512`, and
  * `Spec_Hash_Definitions_SHA1`.

* `prk` Pointer to `HashLen` bytes of memory where pseudorandom key is written to.
* `salt` Pointer to `saltlen` bytes of memory where salt value is read from.
* `saltlen` Length of salt value.
* `ikm` Pointer to `ikmlen` bytes of memory where input keying material is read from.
* `ikmlen` Length of input keying material.

```{doxygenfunction} EverCrypt_HKDF_expand
```

Expand pseudorandom key to desired length.

* `a` Hash function to use. Usually, the same as used in `EverCrypt_HKDF_extract`.
* `okm` Pointer to `len` bytes of memory where output keying material is written to.
* `prk` Pointer to at least `HashLen` bytes of memory where pseudorandom key is read from. Usually, this points to the output from the extract step.
* `prklen` Length of pseudorandom key.
* `info` Pointer to `infolen` bytes of memory where context and application specific information is read from. Can be a zero-length string.
* `infolen` Length of context and application specific information.
* `len` Length of output keying material.

--------------------------------------------------------------------------------

```{doxygenfunction} EverCrypt_HKDF_extract_blake2b
```

```{doxygenfunction} EverCrypt_HKDF_expand_blake2b
```

```{doxygenfunction} EverCrypt_HKDF_extract_blake2s
```

```{doxygenfunction} EverCrypt_HKDF_expand_blake2s
```

```{doxygenfunction} EverCrypt_HKDF_extract_sha2_256
```

```{doxygenfunction} EverCrypt_HKDF_expand_sha2_256
```

```{doxygenfunction} EverCrypt_HKDF_extract_sha2_384
```

```{doxygenfunction} EverCrypt_HKDF_expand_sha2_384
```

```{doxygenfunction} EverCrypt_HKDF_extract_sha2_512
```

```{doxygenfunction} EverCrypt_HKDF_expand_sha2_512
```

```{doxygenfunction} EverCrypt_HKDF_extract_sha1
```

```{doxygenfunction} EverCrypt_HKDF_expand_sha1
```

[rfc 5869]: https://www.rfc-editor.org/rfc/rfc5869
