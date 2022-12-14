# Chacha20-Poly1305

HACL implements the Chacha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) construction specified in [RFC 8439].
The library includes three implementations of this construction, all with the same API, for different platforms.
All memory for the output variables have to be allocated by the caller.

## Available Implementations

`````{tabs}

````{group-tab} 32
```c
#include "Hacl_Chacha20Poly1305_32.h"
```

A portable C implementation that can be compiled and run on any platform that is 32-bit or higher.

This implementation works on all CPUs.
````

````{group-tab} 128
```c
#include "Hacl_Chacha20Poly1305_128.h"
```

A 128-bit vectorized C implementation that can be compiled and run on any platform that supports 128-bit SIMD instructions.

Support for VEC128 is needed. Please see the [HACL Packages book].
````

````{group-tab} 256
```c
#include "Hacl_Chacha20Poly1305_256.h"
```

A 256-bit vectorized C implementation that can be compiled and run on any platform that supports 256-bit SIMD instructions.

Support for VEC256 is needed. Please see the [HACL Packages book].
````
`````

## API Reference

**Example (32)**

```{literalinclude} ../../../../tests/chacha20poly1305.cc
:language: C
:dedent:
:start-after: "// ANCHOR(DEFINE)"
:end-before: "// ANCHOR_END(DEFINE)"
```

```{literalinclude} ../../../../tests/chacha20poly1305.cc
:language: C
:dedent:
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_Chacha20Poly1305_32_aead_encrypt
```
```{doxygenfunction} Hacl_Chacha20Poly1305_32_aead_decrypt
```
````
````{group-tab} 128
```{doxygenfunction} Hacl_Chacha20Poly1305_128_aead_encrypt
```
```{doxygenfunction} Hacl_Chacha20Poly1305_128_aead_decrypt
```
````
````{group-tab} 256
```{doxygenfunction} Hacl_Chacha20Poly1305_256_aead_encrypt
```
```{doxygenfunction} Hacl_Chacha20Poly1305_256_aead_decrypt
```
````
`````

[hacl packages book]: https://tech.cryspen.com/hacl-packages/algorithms.html
[rfc 8439]: https://www.rfc-editor.org/rfc/rfc8439.html
