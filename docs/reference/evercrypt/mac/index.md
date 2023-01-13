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

### API Reference

```C
#include "Hacl_Spec.h"
```

```{doxygentypedef} Spec_Hash_Definitions_hash_alg
```

The available hash functions.

The allowed values with recommended HMAC key length (`KEY_LEN`) and HMAC digest output length (`DIGEST_LEN`) are ...

* `Spec_Hash_Definitions_SHA2_224` (KEY_LEN=64, DIGEST_LEN=28),
* `Spec_Hash_Definitions_SHA2_256` (KEY_LEN=64, DIGEST_LEN=32),
* `Spec_Hash_Definitions_SHA2_384` (KEY_LEN=128, DIGEST_LEN=48),
* `Spec_Hash_Definitions_SHA2_512` (KEY_LEN=128, DIGEST_LEN=64),
* `Spec_Hash_Definitions_SHA1` (KEY_LEN=64, DIGEST_LEN=20),
* `Spec_Hash_Definitions_MD5` (KEY_LEN=64, DIGEST_LEN=16),
* `Spec_Hash_Definitions_Blake2S` (KEY_LEN=64, DIGEST_LEN=32), and
* `Spec_Hash_Definitions_Blake2B` (KEY_LEN=128, DIGEST_LEN=64).

Note that the HMAC key can be of any length and will be preprocessed accordingly before use.

--------------------------------------------------------------------------------

```{doxygenfunction} EverCrypt_HMAC_is_supported_alg
```

Check that a hash function is supported to be used in the HMAC construction.

```{doxygenfunction} EverCrypt_HMAC_compute
```

Write the MAC of a message (`data`) by using the hash algorithm `a` with a key (`key`) into `dst`.
 
The recommended size for the `key` depends on the used hash algorithm (see `KEY_LEN` above).
However, the key can be any length and will be hashed if it is longer and padded if it is shorter.
The length of `dst` depends on the output length of the used hash algorithm (see `DIGEST_LEN` above).

