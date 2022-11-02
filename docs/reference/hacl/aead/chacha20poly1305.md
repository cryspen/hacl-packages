# Chacha20-Poly1305

HACL implements the Chacha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) construction specified in [RFC 8439].
The library includes three implementations of this construction, all with the same API, for different platforms:

* `Hacl_Chacha20Poly1305_32.h` contains the API for the portable C implementation that can be compiled and run on any platform that is 32-bit or higher.
* `Hacl_Chacha20Poly1305_128.h` contains the API for the 128-bit vectorized C implementation that can be compiled and run on any platform that supports 128-bit SIMD instructions.
* `Hacl_Chacha20Poly1305_256.h` contains the API for the 256-bit vectorized C implementation that can be compiled and run on any platform that supports 256-bit SIMD instructions.

All memory for the output variables have to be allocated by the caller.

## Available Implementations

`````{tabs}

````{group-tab} 32
```c
#include "Hacl_Chacha20Poly1305_32.h"
```

This implementation works on all CPUs.
````

````{group-tab} 128
```c
#include "Hacl_Chacha20Poly1305_128.h"
```

Support for VEC128 is needed. Please see the [HACL Packages book].
````

````{group-tab} 256
```c
#include "Hacl_Chacha20Poly1305_256.h"
```

Support for VEC256 is needed. Please see the [HACL Packages book].
````
`````

## Example

```{literalinclude} ../../../../tests/chacha20poly1305.cc
:language: C
:dedent:
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

## API Reference

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Chacha20Poly1305_32_aead_encrypt
```

````

````{group-tab} 128

```{doxygenfunction} Hacl_Chacha20Poly1305_128_aead_encrypt
```

````

````{group-tab} 256

```{doxygenfunction} Hacl_Chacha20Poly1305_256_aead_encrypt
```

````
`````

The first argument `k` is a pointer to the AEAD key (the length of this array MUST be 32 bytes);
`n` is a pointer to the AEAD nonce (the length of this array MUST be 12 bytes);
`aadlen` is the length of the associated data array `aad`;
`mlen` is the length of the input array `m`;
the output ciphertext also has `mlen` bytes and is stored in `cipher`;
the output tag has a length of 16 bytes and is stored in `mac`.
Note that encryption and decryption can be executed in-place, i.e., `m` and `cipher` can point to the same memory.

-------------------------------------------------------------------------------

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Chacha20Poly1305_32_aead_decrypt
```

````

````{group-tab} 128

```{doxygenfunction} Hacl_Chacha20Poly1305_128_aead_decrypt
```

````

````{group-tab} 256

```{doxygenfunction} Hacl_Chacha20Poly1305_256_aead_decrypt
```

````
`````

The arguments `k`, `n`, `aadlen`, and `aad` are the same as in encryption.
The next argument `mlen` is the length of the input ciphertext cipher and `mac` holds the input tag.
If decryption succeeds, the resulting plaintext is stored in `m` and the function returns the success code 0.
If decryption fails, the array `m` remains unchanged and the function returns the error code 1.
Note that encryption and decryption can be executed in-place, i.e., `m` and `cipher` can point to the same memory.

[hacl packages book]: https://tech.cryspen.com/hacl-packages/algorithms.html
[rfc 8439]: https://www.rfc-editor.org/rfc/rfc8439.html
