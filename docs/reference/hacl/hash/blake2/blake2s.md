# Blake2s

BLAKE2s is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes.

## API Reference

### One-Shot

**Available Implementations**

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2s.h"
```
````
````{group-tab} 128
```C
#include "Hacl_Hash_Blake2s_Simd128.h"
```
````
`````

**Example (32)**

```{literalinclude} ../../../../../tests/blake2s.cc
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

```{literalinclude} ../../../../../tests/blake2s.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example)"
:end-before: "// ANCHOR_END(example)"
```

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Hash_Blake2s_hash_with_key
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Hash_Blake2s_Simd128_hash_with_key
```
````
`````

### Streaming (without key)

**Available Implementations**

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2.h"
```
````
````{group-tab} 128
```C
#include "Hacl_Hash_Blake2s_Simd128.h"
```
````
`````

**Example (32)**

```{literalinclude} ../../../../../tests/blake2s.cc
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

```{literalinclude} ../../../../../tests/blake2s.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example streaming)"
:end-before: "// ANCHOR_END(example streaming)"
```

`````{tabs}
````{group-tab} 32
```{doxygentypedef} Hacl_Hash_Blake2s_state_t
```
```{doxygenfunction} Hacl_Hash_Blake2s_malloc
```
```{doxygenfunction} Hacl_Hash_Blake2s_update
```
```{doxygenfunction} Hacl_Hash_Blake2s_digest
```
```{doxygenfunction} Hacl_Hash_Blake2s_reset
```
```{doxygenfunction} Hacl_Hash_Blake2s_free
```
````
````{group-tab} 128
```{doxygentypedef} Hacl_Hash_Blake2s_Simd128_state_t
```
```{doxygenfunction} Hacl_Hash_Blake2s_Simd128_malloc
```
```{doxygenfunction} Hacl_Hash_Blake2s_Simd128_update
```
```{doxygenfunction} Hacl_Hash_Blake2s_Simd128_digest
```
```{doxygenfunction} Hacl_Hash_Blake2s_Simd128_reset
```
```{doxygenfunction} Hacl_Hash_Blake2s_Simd128_free
```
````
`````
