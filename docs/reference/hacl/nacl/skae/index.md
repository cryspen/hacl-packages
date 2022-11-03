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

```{doxygenfunction} Hacl_NaCl_crypto_secretbox_open_easy
```

### Detached mode

In detached mode, the authentication tag and encrypted message are stored separately.
Thus, `c` must always point to `mlen` bytes and `tag` must always point to 16 (tag length) bytes.

```{doxygenfunction} Hacl_NaCl_crypto_secretbox_detached
```

```{doxygenfunction} Hacl_NaCl_crypto_secretbox_open_detached
```

