# Blake2s

BLAKE2s is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes.

## API Reference

### One-Shot

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_Hash_Blake2.h"
```

```{doxygenfunction} Hacl_Blake2s_32_blake2s
```
````

````{group-tab} 128
```C
#include "Hacl_Hash_Blake2s_128.h"
```

```{doxygenfunction} Hacl_Blake2s_128_blake2s
```
````
`````

Write the BLAKE2s digest of the message `d` using the key `k` into `output`.

  `nn` Length of to-be-generated digest (1 < `nn` <= 32).
  `output` Pointer to digest.
  `ll` Length of the input message.
  `d` Pointer to the input message.
  `kk` Length of the key.
  `k` Pointer to the key.

### Streaming (without key)

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

`````{tabs}
````{group-tab} 32
```{doxygentypedef} Hacl_Streaming_Blake2_blake2s_32_state
```
````
````{group-tab} 128
```{doxygentypedef} Hacl_Streaming_Blake2s_128_blake2s_128_state
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_create_in
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_create_in
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_init
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_init
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_update
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_update
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_finish
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_finish
```
````
`````

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Streaming_Blake2_blake2s_32_no_key_free
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Streaming_Blake2s_128_blake2s_128_no_key_free
```
````
`````

