# Blake2b

BLAKE2b is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes.
It also has a build-in keying mechanism so that it can be used to replace HMAC-based constructions.

## API Reference

### One-Shot

**Available Implementations**

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2b.h"
```
````
````{group-tab} 256
```C
#include "Hacl_Hash_Blake2b_Simd256.h"
```
````
`````

**Example (32)**

```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define)"
:end-before: "// ANCHOR_END(example define)"
```

```{literalinclude} ../../../../../tests/util.h
:language: C
:dedent:
:start-after: "// ANCHOR(print_hex_ln)"
:end-before: "// ANCHOR_END(print_hex_ln)"
```

```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example)"
:end-before: "// ANCHOR_END(example)"
```

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Hash_Blake2b_hash_with_key
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Hash_Blake2b_Simd256_hash_with_key
```
````
`````

### Streaming (without key)

**Available Implementations**

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2b.h"
```
````
````{group-tab} 256
```C
#include "Hacl_Hash_Blake2b_Simd256.h"
```
````
`````

**Example (32)**

```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define)"
:end-before: "// ANCHOR_END(example define)"
```

```{literalinclude} ../../../../../tests/util.h
:language: C
:dedent:
:start-after: "// ANCHOR(print_hex_ln)"
:end-before: "// ANCHOR_END(print_hex_ln)"
```

```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example streaming)"
:end-before: "// ANCHOR_END(example streaming)"
```

`````{tabs}
````{group-tab} 32
```{doxygentypedef} Hacl_Hash_Blake2b_state_t
```
```{doxygenfunction} Hacl_Hash_Blake2b_malloc
```
```{doxygenfunction} Hacl_Hash_Blake2b_update
```
```{doxygenfunction} Hacl_Hash_Blake2b_digest
```
```{doxygenfunction} Hacl_Hash_Blake2b_reset
```
```{doxygenfunction} Hacl_Hash_Blake2b_free
```
````
````{group-tab} 256
```{doxygentypedef} Hacl_Hash_Blake2b_Simd256_state_t
```
```{doxygenfunction} Hacl_Hash_Blake2b_Simd256_malloc
```
```{doxygenfunction} Hacl_Hash_Blake2b_Simd256_update
```
```{doxygenfunction} Hacl_Hash_Blake2b_Simd256_digest
```
```{doxygenfunction} Hacl_Hash_Blake2b_Simd256_reset
```
```{doxygenfunction} Hacl_Hash_Blake2b_Simd256_free
```
````
`````
