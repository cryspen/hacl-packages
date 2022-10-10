# KDF

Key derivation functions (KDFs) are used to derive cryptographically strong keys from an initial secret value.

## HKDF

HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869].

Similar to [RFC 5869], the following descriptions use the term `HashLen` to denote the output length of the hash function of a concrete innstantiation of HKDF.

The following instantiations are supported:

* BLAKE2b (`HashLen` = 64)
* BLAKE2s (`HashLen` = 32)
* SHA2-256 (`HashLen` = 32)
* SHA2-512 (`HashLen` = 64)

### API Reference

#### BLAKE2b

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_extract_blake2b_32
```
````

````{group-tab} 256
```C
#include "Hacl_HKDF_Blake2b_256.h"
```

```{doxygenfunction} Hacl_HKDF_Blake2b_256_extract_blake2b_256
```
````
`````

Extract a fixed-length pseudorandom key from input keying material.

* `prk` Pointer to `HashLen` bytes of memory where pseudorandom key is written to.
* `salt` Pointer to `saltlen` bytes of memory where salt value is read from.
* `saltlen` Length of salt value.
* `ikm` Pointer to `ikmlen` bytes of memory where input keying material is read from.
* `ikmlen` Length of input keying material.

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_expand_blake2b_32
```
````

````{group-tab} 256
```C
#include "Hacl_HKDF_Blake2b_256.h"
```

```{doxygenfunction} Hacl_HKDF_Blake2b_256_expand_blake2b_256
```
````
`````

Expand pseudorandom key to desired length.

* `okm` Pointer to `len` bytes of memory where output keying material is written to.
* `prk` Pointer to at least `HashLen` bytes of memory where pseudorandom key is read from. Usually, this points to the output from the extract step.
* `prklen` Length of pseudorandom key.
* `info` Pointer to `infolen` bytes of memory where context and application specific information is read from. Can be a zero-length string.
* `infolen` Length of context and application specific information.
* `len` Length of output keying material.

#### BLAKE2s

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_extract_blake2s_32
```
````

````{group-tab} 128
```C
#include "Hacl_HKDF_Blake2s_128.h"
```

```{doxygenfunction} Hacl_HKDF_Blake2s_128_extract_blake2s_128
```
````
`````

Extract a fixed-length pseudorandom key from input keying material.

* `prk` Pointer to `HashLen` bytes of memory where pseudorandom key is written to.
* `salt` Pointer to `saltlen` bytes of memory where salt value is read from.
* `saltlen` Length of salt value.
* `ikm` Pointer to `ikmlen` bytes of memory where input keying material is read from.
* `ikmlen` Length of input keying material.

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_expand_blake2s_32
```
````

````{group-tab} 128
```C
#include "Hacl_HKDF_Blake2s_128.h"
```

```{doxygenfunction} Hacl_HKDF_Blake2s_128_expand_blake2s_128
```
````
`````
Expand pseudorandom key to desired length.

* `okm` Pointer to `len` bytes of memory where output keying material is written to.
* `prk` Pointer to at least `HashLen` bytes of memory where pseudorandom key is read from. Usually, this points to the output from the extract step.
* `prklen` Length of pseudorandom key.
* `info` Pointer to `infolen` bytes of memory where context and application specific information is read from. Can be a zero-length string.
* `infolen` Length of context and application specific information.
* `len` Length of output keying material.


#### SHA2-256

```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_extract_sha2_256
```

Extract a fixed-length pseudorandom key from input keying material.

* `prk` Pointer to `HashLen` bytes of memory where pseudorandom key is written to.
* `salt` Pointer to `saltlen` bytes of memory where salt value is read from.
* `saltlen` Length of salt value.
* `ikm` Pointer to `ikmlen` bytes of memory where input keying material is read from.
* `ikmlen` Length of input keying material.

```{doxygenfunction} Hacl_HKDF_expand_sha2_256
```

Expand pseudorandom key to desired length.

* `okm` Pointer to `len` bytes of memory where output keying material is written to.
* `prk` Pointer to at least `HashLen` bytes of memory where pseudorandom key is read from. Usually, this points to the output from the extract step.
* `prklen` Length of pseudorandom key.
* `info` Pointer to `infolen` bytes of memory where context and application specific information is read from. Can be a zero-length string.
* `infolen` Length of context and application specific information.
* `len` Length of output keying material.

#### SHA2-512

```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_extract_sha2_512
```

Extract a fixed-length pseudorandom key from input keying material.

* `prk` Pointer to `HashLen` bytes of memory where pseudorandom key is written to.
* `salt` Pointer to `saltlen` bytes of memory where salt value is read from.
* `saltlen` Length of salt value.
* `ikm` Pointer to `ikmlen` bytes of memory where input keying material is read from.
* `ikmlen` Length of input keying material.

```{doxygenfunction} Hacl_HKDF_expand_sha2_512
```

Expand pseudorandom key to desired length.

* `okm` Pointer to `len` bytes of memory where output keying material is written to.
* `prk` Pointer to at least `HashLen` bytes of memory where pseudorandom key is read from. Usually, this points to the output from the extract step.
* `prklen` Length of pseudorandom key.
* `info` Pointer to `infolen` bytes of memory where context and application specific information is read from. Can be a zero-length string.
* `infolen` Length of context and application specific information.
* `len` Length of output keying material.

[rfc 5869]: https://www.rfc-editor.org/rfc/rfc5869
