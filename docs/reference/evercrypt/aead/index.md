# AEAD (``EverCrypt_AEAD.h``)

Clients are expected to allocate persistent state first, which performs key expansion and precomputes internal data, e.g., for AES-GCM.
`UnsupportedAlgorithm` may be returned because of an unsupported algorithm (e.g. AES-CCM), or because no implementation is available for the target platform (e.g. AES-GCM without ADX+BMI2).
State must be finally freed via the `EverCrypt_AEAD_free` function.

## API Reference

**State management**

```{doxygentypedef} EverCrypt_AEAD_state_s
```

Both encryption and decryption take a piece of state which holds the key.
The state may be reused as many times as desired.

```{doxygenfunction} EverCrypt_AEAD_create_in
```

The argument `a` must be either of:
* `Spec_Agile_AEAD_AES128_GCM`,
* `Spec_Agile_AEAD_AES256_GCM`, or
* `Spec_Agile_AEAD_CHACHA20_POLY1305`.

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

Encrypt and authenticate a message (`plain`) with associated data (`ad`).

`s` is the AEAD state created by `EverCrypt_AEAD_create_in` and already contains the encryption key.
`iv` is the nonce required for encryption.
Note: ChaCha20Poly1305 requires a 12 byte iv.
`ad` is the associated data that should be authenticated (not encrypted) alongside the ciphertext.
`plain` is the to-be-encrypted plaintext.

The resulting ciphertext will be written into `cipher` and the mac/tag will be written into `tag`.
Note: The length of the `tag` array must be of a suitable length for the chosen algorithm.
There is no length parameter for the `tag`.

`EverCrypt_AEAD_encrypt` may return either `Success` or `InvalidKey`.
The latter is returned if and only if the `s` parameter is `NULL`.

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

Verify the authenticity of `ad` || `cipher` and decrypt `cipher` into `dst`.

`s` is the AEAD state created by `EverCrypt_AEAD_create_in` and already contains the decryption key.
`iv` is the nonce required for decryption.
`ad` is the associated data that was authenticated (not encrypted) alongside the ciphertext.
`cipher` is the to-be-decrypted ciphertext.
`tag` is the tag/mac generated during encryption.
Upon success, the plaintext will be written into `dst`.
Note: The length of `dst` must be equal to the length of `cipher`.

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

