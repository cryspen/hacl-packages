# AEAD

EverCrypt provides multiple Authenticated Encryption with Associated Data (AEAD) algorithms, i.e., ...

* ChaCha20Poly1305,
* AES128-GCM, and
* AES256-GCM

... via a unified interface.

In this interface, clients are expected to allocate an AEAD context (state) first, which performs key expansion and precomputes internal data, e.g., for AES-GCM.
`UnsupportedAlgorithm` may be returned because of an unsupported algorithm, or because no implementation is available for the target platform (e.g. AES-GCM without ADX+BMI2).
The state must finally be freed via the `EverCrypt_AEAD_free` function.

## API Reference

**State management**

```{doxygentypedef} EverCrypt_AEAD_state_s
```

Both encryption and decryption take a piece of state that holds the key.
The state may be reused as many times as desired.

```{doxygenfunction} EverCrypt_AEAD_create_in
```

```{doxygenfunction} EverCrypt_AEAD_alg_of_state
```

Return the algorithm used in the AEAD state.

```{doxygenfunction} EverCrypt_AEAD_free
```

Cleanup and free the AEAD state.

--------------------------------------------------------------------------------

**Encryption**

```{doxygenfunction} EverCrypt_AEAD_encrypt
```

<!--
```{doxygenfunction} EverCrypt_Chacha20Poly1305_aead_encrypt
```

```{doxygenfunction} EverCrypt_AEAD_encrypt_expand
```

```{doxygenfunction} EverCrypt_AEAD_encrypt_expand_aes128_gcm
```

```{doxygenfunction} EverCrypt_AEAD_encrypt_expand_aes256_gcm
```

```{doxygenfunction} EverCrypt_AEAD_encrypt_expand_chacha20_poly1305
```
-->

--------------------------------------------------------------------------------

**Decryption**

```{doxygenfunction} EverCrypt_AEAD_decrypt
```

<!--
```{doxygenfunction} EverCrypt_Chacha20Poly1305_aead_decrypt
```

```{doxygenfunction} EverCrypt_AEAD_decrypt_expand
```

```{doxygenfunction} EverCrypt_AEAD_decrypt_expand_aes128_gcm
```

```{doxygenfunction} EverCrypt_AEAD_decrypt_expand_aes256_gcm
```

```{doxygenfunction} EverCrypt_AEAD_decrypt_expand_chacha20_poly1305
```
-->

