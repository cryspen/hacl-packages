# Blake2b

BLAKE2b is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes.
It also has a build-in keying mechanism so that it can be used to replace HMAC-based constructions.

## Example

The following example shows how to use the one-shot API with the base implementation (32) of BLAKE2b.

```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// API EXAMPLE INCLUDE START"
:end-before: "// API EXAMPLE INCLUDE END"
```

```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// API EXAMPLE HEX START"
:end-before: "// API EXAMPLE HEX END"
```

```{literalinclude} ../../../../../tests/blake2b.cc
:language: C
:dedent:
:start-after: "// API EXAMPLE CODE START"
:end-before: "// API EXAMPLE CODE END"
```

## API Reference

### One-Shot

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2.h"
```

```{doxygenfunction} Hacl_Blake2b_32_blake2b
```
````
````{group-tab} 256
```C
#include "Hacl_Hash_Blake2b_256.h"
```
```{doxygenfunction} Hacl_Blake2b_256_blake2b
```
````
`````

### Streaming (without key)


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

`````{tabs}
````{group-tab} 32
```{doxygentypedef} Hacl_Streaming_Blake2_blake2b_32_state
```
````
````{group-tab} 256
```{doxygentypedef} Hacl_Streaming_Blake2b_256_blake2b_256_state
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_create_in
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_create_in
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_init
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_init
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_update
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_update
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_finish
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_finish
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2b_32_no_key_free
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Streaming_Blake2b_256_blake2b_256_no_key_free
```
````
`````

