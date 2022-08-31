# AEAD

In HACL there is no multiplexing API for AEADs.
Instead each algorithm and version have to be called explicitly.

## Chacha20-Poly1305

HACL implements the Chacha20-Poly1305 Authenticated Encryption
with Associated Data (AEAD) construction
specified in [RFC 8439].
The library includes three implementations of this construction,
all with the same API, for different platforms:

- `Hacl_Chacha20Poly1305_32.h` contains the API for the portable C implementation that can be compiled and run on any platform that is 32-bit or higher.
- `Hacl_Chacha20Poly1305_128.h` contains the API for the 128-bit vectorized C implementation that can be compiled and run on any platform that supports `Vec128`.
- `Hacl_Chacha20Poly1305_256.h` contains the API for the 256-bit vectorized C implementation that can be compiled and run on any platform that supports `Vec256`.

All memory for the output variables have to be allocated by the caller.

### Encryption

```c
void
Hacl_Chacha20Poly1305_32_aead_encrypt(
  uint8_t *k,
  uint8_t *n,
  uint32_t aadlen,
  uint8_t *aad,
  uint32_t mlen,
  uint8_t *m,
  uint8_t *cipher,
  uint8_t *mac
);

void Hacl_Chacha20Poly1305_128_aead_encrypt(...);
void Hacl_Chacha20Poly1305_256_aead_encrypt(...);
```

The first argument `k` is a pointer to the AEAD key (the length of this array
MUST be 32 bytes);
`n` is a pointer to the AEAD nonce (the length of this array MUST be 12 bytes);
`aadlen` is the length of the associated data array `aad`;
`mlen` is the length of the input array `m`;
the output ciphertext also has `mlen` bytes and is stored in `cipher`;
the output tag has a length of 16 bytes and is stored in `mac`.

### Decryption

```c
uint32_t
Hacl_Chacha20Poly1305_32_aead_decrypt(
  uint8_t *k,
  uint8_t *n,
  uint32_t aadlen,
  uint8_t *aad,
  uint32_t mlen,
  uint8_t *m,
  uint8_t *cipher,
  uint8_t *mac
);

void Hacl_Chacha20Poly1305_128_aead_decrypt(...);
void Hacl_Chacha20Poly1305_256_aead_decrypt(...);
```

The arguments `k`, `n`, `aadlen`, and `aad` are the same as in encryption.
The next argument `mlen` is the length of the input ciphertext `cipher` and
`mac` holds the input tag.
If decryption succeeds, the resulting plaintext is stored in `m` and the
function returns the success code `0`.
If decryption fails, the array `m` remains unchanged and the function returns
the error code `1`.

[rfc 8439]: https://tools.ietf.org/html/rfc8439
