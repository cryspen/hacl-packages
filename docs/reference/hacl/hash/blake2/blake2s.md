# Blake2s

BLAKE2s is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes.

## API Reference

### One-Shot

**Available Implementations**

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2.h"
```
````
````{group-tab} 128
```C
#include "Hacl_Hash_Blake2s_128.h"
```
````
`````

**Example**

`````{tabs}
````{group-tab} 32
```{literalinclude} ../../../../../tests/blake2s.cc
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

```{literalinclude} ../../../../../tests/blake2s.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example)"
:end-before: "// ANCHOR_END(example)"
```

````
````{group-tab} 128
There is no example for now.
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Blake2s_32_blake2s
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Blake2s_128_blake2s
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
````{group-tab} 128
```C
#include "Hacl_Streaming_Blake2s_128.h"
```
````
`````

**Example**

`````{tabs}
````{group-tab} 32
There is no example for now.
````
````{group-tab} 128
There is no example for now.
````
`````

`````{tabs}
````{group-tab} 32
```{doxygentypedef} Hacl_Streaming_Blake2_blake2s_32_state
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_create_in
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_init
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_update
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_finish
```
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_free
```
````
````{group-tab} 128
```{doxygentypedef} Hacl_Streaming_Blake2s_128_blake2s_128_state
```
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_create_in
```
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_init
```
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_update
```
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_finish
```
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_free
```
````
`````
