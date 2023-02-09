# KDF

Key derivation functions (KDFs) are used to derive cryptographically strong keys from an initial secret value.

## HKDF

HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869].

Similar to [RFC 5869], the following descriptions uses the term `HashLen` to denote the output length of the hash function of a concrete instantiation of HKDF.

The following instantiations are supported:

* BLAKE2b (`HashLen` = 64)
* BLAKE2s (`HashLen` = 32)
* SHA2-256 (`HashLen` = 32)
* SHA2-384 (`HashLen` = 48)
* SHA2-512 (`HashLen` = 64)

### Available Implementations

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_HKDF.h"
```
````

````{group-tab} 256
```C
#include "Hacl_HKDF_Blake2b_256.h"
```
````
`````

### API Reference

**Example (SHA2-256)**

```{literalinclude} ../../../../tests/hkdf.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE DEFINE)"
:end-before: "// ANCHOR_END(EXAMPLE DEFINE)"
```

```{literalinclude} ../../../../tests/hkdf.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE)"
:end-before: "// ANCHOR_END(EXAMPLE)"
```

#### BLAKE2b

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_HKDF_extract_blake2b_32
```
````

````{group-tab} 256
```{doxygenfunction} Hacl_HKDF_Blake2b_256_extract_blake2b_256
```
````
`````

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

#### SHA2-256

```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_extract_sha2_256
```

```{doxygenfunction} Hacl_HKDF_expand_sha2_256
```

#### SHA2-384

```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_extract_sha2_384
```

```{doxygenfunction} Hacl_HKDF_expand_sha2_384
```

#### SHA2-512

```C
#include "Hacl_HKDF.h"
```

```{doxygenfunction} Hacl_HKDF_extract_sha2_512
```

```{doxygenfunction} Hacl_HKDF_expand_sha2_512
```

[rfc 5869]: https://www.rfc-editor.org/rfc/rfc5869
