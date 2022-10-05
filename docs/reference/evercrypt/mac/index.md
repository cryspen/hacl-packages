# MAC

A Message Authentication Code (MAC) provides data integrity and authenticity of a message.

## HMAC

An HMAC is a specific construction of a MAC that involves a cryptographic hash function (see [RFC 2104]).
Thus, an HMAC comes in multiple instantiations.
HACL Packages supports the following ones:

* HMAC-BLAKE2b,
* HMAC-BLAKE2s,
* HMAC-SHA-2-256,
* HMAC-SHA-2-384,
* HMAC-SHA-2-512, and
* HMAC-SHA-1.

Keys must be chosen using a cryptographically strong pseudo-random generator and periodically refreshed.

# HMAC

## API Reference

```C
#include "Hacl_Spec.h"
```

```{doxygentypedef} Spec_Hash_Definitions_hash_alg
```

The available hash functions.

The allowed values are ...

* `Spec_Hash_Definitions_SHA2_224`,
* `Spec_Hash_Definitions_SHA2_256`,
* `Spec_Hash_Definitions_SHA2_384`,
* `Spec_Hash_Definitions_SHA2_512`,
* `Spec_Hash_Definitions_SHA1`,
* `Spec_Hash_Definitions_MD5`,
* `Spec_Hash_Definitions_Blake2S`, and
* `Spec_Hash_Definitions_Blake2B`.

--------------------------------------------------------------------------------

```{doxygenfunction} EverCrypt_HMAC_is_supported_alg
```

Check that a hash function is supported to be used in the HMAC construction.

```{doxygenfunction} EverCrypt_HMAC_compute
```

Write the MAC of a message (`data`) by using the hash algorithm `a` with a key (`key`) into `dst`.
 
The recommended size for the `key` depends on the used hash algorithm (see below).
However, the key can be any length and will be hashed if it is longer and padded if it is shorter.
The length of `dst` depends on the output length of the used hash algorithm (see below).

--------------------------------------------------------------------------------

# BLAKE2b

```{doxygenfunction} EverCrypt_HMAC_compute_blake2b
```

The key can be any length and will be hashed if it is longer and padded if it is shorter than 128 bytes.
`dst` must point to 64 bytes of memory.

--------------------------------------------------------------------------------

# BLAKE2s


```{doxygenfunction} EverCrypt_HMAC_compute_blake2s
```

The key can be any length and will be hashed if it is longer and padded if it is shorter than 64 bytes.
`dst` must point to 32 bytes of memory.

--------------------------------------------------------------------------------

# SHA-2

```{doxygenfunction} EverCrypt_HMAC_compute_sha2_256
```

The key can be any length and will be hashed if it is longer and padded if it is shorter than 64 bytes.
`dst` must point to 32 bytes of memory.

```{doxygenfunction} EverCrypt_HMAC_compute_sha2_384
```

The key can be any length and will be hashed if it is longer and padded if it is shorter than 128 bytes.
`dst` must point to 48 bytes of memory.

```{doxygenfunction} EverCrypt_HMAC_compute_sha2_512
```

The key can be any length and will be hashed if it is longer and padded if it is shorter than 128 bytes.
`dst` must point to 64 bytes of memory.

--------------------------------------------------------------------------------

# SHA-1

```{doxygenfunction} EverCrypt_HMAC_compute_sha1
```

The key can be any length and will be hashed if it is longer and padded if it is shorter than 64 bytes.
`dst` must point to 20 bytes of memory.
