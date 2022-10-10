# Secret-key Authenticated Encryption

Secret-key Authenticated Encryption (Secret Box).

This module provides a combined- and detached API.
Please make sure that you use the correct pairs of functions to encrypt and decrypt messages as these APIs are not meant to be mixed.

Furthermore, NaCl supports in-place encryption/decryption.
Thus, the message and ciphertext are allowed to overlap.

## API Reference

### Combined mode

In combined mode, the authentication tag and encrypted message are stored consecutively in memory.
Thus, `c` must always point to memory with length 16 (tag length) + `mlen` (message length).

```{doxygenfunction} Hacl_NaCl_crypto_secretbox_easy
```

Encrypt a message with a key and nonce.

* `c` Pointer to 16 (tag length) + `mlen` bytes where the ciphertext is written to.
* `m` Pointer to `mlen` bytes where the message is read from.
* `mlen` Length of message.
* `n` Pointer to 24 (`crypto_secretbox_NONCEBYTES`) bytes where the nonce is read from.
* `k` Pointer to 32 (`crypto_secretbox_KEYBYTES`) bytes where the key is read from.

```{doxygenfunction} Hacl_NaCl_crypto_secretbox_open_easy
```

Verify and decrypt a ciphertext produced with `Hacl_NaCl_crypto_secretbox_easy`.

* `m` Pointer to `mlen` bytes where the message is written to.
* `c` Pointer to `clen` bytes where the ciphertext is read from. The authentication tag must be included.
* `clen` Length of ciphertext.
* `n` Pointer to 24 (`crypto_secretbox_NONCEBYTES`) bytes where the nonce is read from.
* `k` Pointer to 32 (`crypto_secretbox_KEYBYTES`) bytes where the key is read from.

### Detached mode

In detached mode, the authentication tag and encrypted message are stored separately.
Thus, `c` must always point to `mlen` bytes and `tag` must always point to 16 (tag length) bytes.

```{doxygenfunction} Hacl_NaCl_crypto_secretbox_detached
```

Encrypt a message with a key and nonce.

* `c` Pointer to `mlen` bytes where the ciphertext is written to.
* `tag` Pointer to 16 (tag length) bytes where the authentication tag is written to.
* `m` Pointer to `mlen` bytes where the message is read from.
* `mlen` Length of message.
* `n` Pointer to 24 (`crypto_secretbox_NONCEBYTES`) bytes where the nonce is read from.
* `k` Pointer to 32 (`crypto_secretbox_KEYBYTES`) bytes where the key is read from.

```{doxygenfunction} Hacl_NaCl_crypto_secretbox_open_detached
```

Verify and decrypt a ciphertext produced with `Hacl_NaCl_crypto_secretbox_detached`.

* `m` Pointer to `mlen` bytes where the message is written to.
* `c` Pointer to `mlen` bytes where the ciphertext is read from.
* `tag` Pointer to 16 (tag length) bytes where the authentication tag is read from.
* `mlen` Length of message (and ciphertext).
* `n` Pointer to 24 (`crypto_secretbox_NONCEBYTES`) bytes where the nonce is read from.
* `k` Pointer to 32 (`crypto_secretbox_KEYBYTES`) bytes where the key is read from.

