# Public-key Authenticated Encryption

Public-key authenticated encryption (Crypto Box).

This module provides a combined- and detached API with and without precomputation.
Please make sure that you use the correct pairs of functions to encrypt and decrypt messages as these APIs are not meant to be mixed.

Furthermore, NaCl supports in-place encryption/decryption.
Thus, the message and ciphertext are allowed to overlap.

## API Reference

### Combined mode

In combined mode, the authentication tag and encrypted message are stored consecutively in memory.
Thus, `c` must always point to memory with length 16 (tag length) + `mlen` (message length).

```{doxygenfunction} Hacl_NaCl_crypto_box_easy
```

Encrypt a message using the recipient's public key, the sender's secret key, and a nonce.

* `c` Pointer to 16 (tag length) + `mlen` bytes of memory where the authentication tag and ciphertext is written to.
* `m` Pointer to `mlen` bytes of memory where the message is read from.
* `mlen` Length of the message.
* `n` Pointer to 24 (`crypto_box_NONCEBYTES`) bytes of memory where the nonce is read from.
* `pk` Pointer to public key of the recipient.
* `sk` Pointer to secret key of the sender.

```{doxygenfunction} Hacl_NaCl_crypto_box_open_easy
```

Verify and decrypt a ciphertext produced by `Hacl_NaCl_crypto_box_easy`.

* `m` Pointer to `clen` - 16 (tag length) bytes of memory where the decrypted message is written to.
* `c` Pointer to `clen` bytes of memory where the ciphertext is read from. Note: the ciphertext must include the tag.
* `clen` Length of the ciphertext.
* `n` Pointer to 24 (`crypto_box_NONCEBYTES`) bytes of memory where the nonce is read from.
* `pk` Pointer to public key of the sender.
* `sk` Pointer to secret key of the recipient.

### Detached mode

In detached mode, the authentication tag and encrypted message are stored separately.
Thus, `c` must always point to `mlen` bytes of memory and `tag` must always point to 16 (tag length) bytes of memory.

Note: NaCl supports in-place encryption/decryption.
Thus, the message and ciphertext are allowed to overlap.

```{doxygenfunction} Hacl_NaCl_crypto_box_detached
```

Encrypt a message using the recipient's public key, the sender's secret key, and a nonce.

* `c` Pointer to `mlen` bytes of memory where the ciphertext is written to.
* `tag` Pointer to 16 (tag length) bytes of memory where the authentication tag is written to.
* `m` Pointer to `mlen` bytes of memory where the message is read from.
* `mlen` Length of the message.
* `n` Pointer to 24 (`crypto_box_NONCEBYTES`) bytes of memory where the nonce is read from.
* `pk` Pointer to **their** public key.
* `sk` Pointer to **my** secret key.

```{doxygenfunction} Hacl_NaCl_crypto_box_open_detached
```

Verify and decrypt a ciphertext produced by `Hacl_NaCl_crypto_box_detached`.

* `m` Pointer to `mlen` bytes of memory where the decrypted message is written to.
* `c` Pointer to `mlen` bytes of memory where the ciphertext is read from. Note: the ciphertext must include the tag.
* `tag` Pointer to 16 (tag length) bytes of memory where the authentication tag is read from.
* `mlen` Length of the message (and ciphertext).
* `n` Pointer to 24 (`crypto_box_NONCEBYTES`) bytes of memory where the nonce is read from.
* `pk` Pointer to public key of the sender.
* `sk` Pointer to secret key of the recipient.

### With Precomputation

Applications that send several messages to the same recipient or receive several messages from the same sender can precompute a shared secret `k` once and reuse it in subsequent `_afternm` calls to increase performance.

```{doxygenfunction} Hacl_NaCl_crypto_box_beforenm
```

Compute a shared secret key given a public key and secret key.

* `k` Pointer to 32 (`crypto_box_BEFORENMBYTES`) bytes of memory where the shared secret is written to.
* `pk` Pointer to **their** public key.
* `sk` Pointer to **my** secret key.

#### Combined mode

```{doxygenfunction} Hacl_NaCl_crypto_box_easy_afternm
```

See above.

```{doxygenfunction} Hacl_NaCl_crypto_box_open_easy_afternm
```

See above.

#### Detached mode

```{doxygenfunction} Hacl_NaCl_crypto_box_detached_afternm
```

See above.

```{doxygenfunction} Hacl_NaCl_crypto_box_open_detached_afternm
```

See above.
