<!-- Note: There seems to be an easier API, i.e., one the one without `_Incremental`.
However, it doesnt't seem to accept variable length chunks. That's why this one is described here. -->

# Hash

EverCrypt provides multiple hash algorithms, i.e., ...

* Blake2B,
* Blake2S,
* SHA2-224,
* SHA2-256,
* SHA2-384,
* SHA2-512,
* SHA1, and
* MD5

... via a unified interface.

## Typedefs

```{doxygendefine} Spec_Hash_Definitions_SHA2_224
```

```{doxygendefine} Spec_Hash_Definitions_SHA2_256
```

```{doxygendefine} Spec_Hash_Definitions_SHA2_384
```

```{doxygendefine} Spec_Hash_Definitions_SHA2_512
```

```{doxygendefine} Spec_Hash_Definitions_SHA1
```

```{doxygendefine} Spec_Hash_Definitions_MD5
```

```{doxygendefine} Spec_Hash_Definitions_Blake2S
```

```{doxygendefine} Spec_Hash_Definitions_Blake2B
```

```{doxygentypedef} EverCrypt_Hash_Incremental_state_t
```

## Functions

<!-- EverCrypt_Hash_string_of_alg, EverCrypt_Hash_uu___is_MD5_s, EverCrypt_Hash_uu___is_SHA1_s, EverCrypt_Hash_uu___is_SHA2_224_s, EverCrypt_Hash_uu___is_SHA2_256_s, EverCrypt_Hash_uu___is_SHA2_384_s, EverCrypt_Hash_uu___is_SHA2_512_s, EverCrypt_Hash_uu___is_Blake2S_s, EverCrypt_Hash_uu___is_Blake2S_128_s, EverCrypt_Hash_uu___is_Blake2B_s, EverCrypt_Hash_uu___is_Blake2B_256_s, EverCrypt_Hash_alg_of_state, EverCrypt_Hash_create_in, EverCrypt_Hash_create, EverCrypt_Hash_init, EverCrypt_Hash_update_multi_256, EverCrypt_Hash_update, EverCrypt_Hash_update_multi, EverCrypt_Hash_update_last_256, EverCrypt_Hash_update_last, EverCrypt_Hash_finish, EverCrypt_Hash_free, EverCrypt_Hash_copy, EverCrypt_Hash_hash_256, EverCrypt_Hash_hash_224, EverCrypt_Hash_hash, EverCrypt_Hash_Incremental_hash_len, EverCrypt_Hash_Incremental_block_len, EverCrypt_Hash_Incremental_malloc, EverCrypt_Hash_Incremental_reset, EverCrypt_Hash_Incremental_update, EverCrypt_Hash_Incremental_finish_md5, EverCrypt_Hash_Incremental_finish_sha1, EverCrypt_Hash_Incremental_finish_sha224, EverCrypt_Hash_Incremental_finish_sha256, EverCrypt_Hash_Incremental_finish_sha384, EverCrypt_Hash_Incremental_finish_sha512, EverCrypt_Hash_Incremental_finish_blake2s, EverCrypt_Hash_Incremental_finish_blake2b, EverCrypt_Hash_Incremental_alg_of_state, EverCrypt_Hash_Incremental_digest, EverCrypt_Hash_Incremental_free -->

```{doxygenfunction} EverCrypt_Hash_Incremental_hash
```

`a` Algorithm to use.
`dst` Pointer to digest.
`input` Pointer to message.
`len` Length of message.

--------------------------------------------------------------------------------

```{doxygenfunction} EverCrypt_Hash_Incremental_malloc
```

Create a hash state.

`a` Algorithm to use.

```{doxygenfunction} EverCrypt_Hash_Incremental_reset
```

Reset hash state).

`s` The hash state.

```{doxygenfunction} EverCrypt_Hash_Incremental_update
```

Feed the next chunk of the message that will be hashed.

`p` The hash state.
`data` Pointer to the next chunk of the message that will be hashed.
`len` Length of the next chunk of the message that will be hashed.

```{doxygenfunction} EverCrypt_Hash_Incremental_digest
```

Finish the hash calculation and write the digest to `dst`.

`s` The hash state.
`dst` Pointer to digest.

```{doxygenfunction} EverCrypt_Hash_Incremental_free
```

Cleanup the hash state.

`s` The hash state.

```{doxygenfunction} EverCrypt_Hash_Incremental_hash_len
```

```{doxygenfunction} EverCrypt_Hash_Incremental_alg_of_state
```

