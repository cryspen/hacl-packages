# Blake2b

BLAKE2b is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes.
It also has a build-in keying mechanism so that it can be used to replace HMAC-based constructions.

## API Reference

### One-Shot

**Available Implementations**

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2.h"
```
````
````{group-tab} 256
```C
#include "Hacl_Hash_Blake2b_256.h"
```
````
`````

**Example**

`````{tabs}
````{group-tab} 32
```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example header)"
:end-before: "// ANCHOR_END(example header)"
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
````
````{group-tab} 256
There is no example for now.
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Blake2b_32_blake2b
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Blake2b_256_blake2b
```
````
`````

### Streaming (without key)

**Available Implementations**

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Streaming_Blake2.h"
```
````
````{group-tab} 256
```C
#include "Hacl_Streaming_Blake2b_256.h"
```
````
`````

**Example**

`````{tabs}
````{group-tab} 32
There is no example for now.
````
````{group-tab} 256
There is no example for now.
````
`````

`````{tabs}
````{group-tab} 32
```{doxygentypedef} Hacl_Streaming_Blake2_blake2b_32_state
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_create_in
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_init
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_update
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_finish
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_free
```
````
````{group-tab} 256
```{doxygentypedef} Hacl_Streaming_Blake2b_256_blake2b_256_state
```
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_create_in
```
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_init
```
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_update
```
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_finish
```
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_free
```
````
`````
