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

# Typedefs

<!-- EverCrypt_Hash_alg, EverCrypt_Hash_broken_alg, EverCrypt_Hash_alg13, EverCrypt_Hash_e_alg, EverCrypt_Hash_state_s, EverCrypt_Hash_state, Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____, EverCrypt_Hash_Incremental_state -->

```{doxygentypedef} Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____
```

State to hold incremental state.

```{doxygentypedef} EverCrypt_Hash_alg
```

<!-- Spec_Hash_Definitions_SHA2_224, Spec_Hash_Definitions_SHA2_256, Spec_Hash_Definitions_SHA2_384, Spec_Hash_Definitions_SHA2_512, Spec_Hash_Definitions_SHA1, Spec_Hash_Definitions_MD5, Spec_Hash_Definitions_Blake2S, Spec_Hash_Definitions_Blake2B -->

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

```{doxygentypedef} EverCrypt_Hash_broken_alg
```

```{doxygentypedef} EverCrypt_Hash_alg13
```

```{doxygentypedef} EverCrypt_Hash_e_alg
```

```{doxygentypedef} EverCrypt_Hash_state_s
```

```{doxygentypedef} EverCrypt_Hash_state
```

```{doxygentypedef} EverCrypt_Hash_Incremental_state
```

# Functions

<!-- EverCrypt_Hash_string_of_alg, EverCrypt_Hash_uu___is_MD5_s, EverCrypt_Hash_uu___is_SHA1_s, EverCrypt_Hash_uu___is_SHA2_224_s, EverCrypt_Hash_uu___is_SHA2_256_s, EverCrypt_Hash_uu___is_SHA2_384_s, EverCrypt_Hash_uu___is_SHA2_512_s, EverCrypt_Hash_uu___is_Blake2S_s, EverCrypt_Hash_uu___is_Blake2S_128_s, EverCrypt_Hash_uu___is_Blake2B_s, EverCrypt_Hash_uu___is_Blake2B_256_s, EverCrypt_Hash_alg_of_state, EverCrypt_Hash_create_in, EverCrypt_Hash_create, EverCrypt_Hash_init, EverCrypt_Hash_update_multi_256, EverCrypt_Hash_update2, EverCrypt_Hash_update, EverCrypt_Hash_update_multi2, EverCrypt_Hash_update_multi, EverCrypt_Hash_update_last_256, EverCrypt_Hash_update_last2, EverCrypt_Hash_update_last, EverCrypt_Hash_finish, EverCrypt_Hash_free, EverCrypt_Hash_copy, EverCrypt_Hash_hash_256, EverCrypt_Hash_hash_224, EverCrypt_Hash_hash, EverCrypt_Hash_Incremental_hash_len, EverCrypt_Hash_Incremental_block_len, EverCrypt_Hash_Incremental_create_in, EverCrypt_Hash_Incremental_init, EverCrypt_Hash_Incremental_update, EverCrypt_Hash_Incremental_finish_md5, EverCrypt_Hash_Incremental_finish_sha1, EverCrypt_Hash_Incremental_finish_sha224, EverCrypt_Hash_Incremental_finish_sha256, EverCrypt_Hash_Incremental_finish_sha384, EverCrypt_Hash_Incremental_finish_sha512, EverCrypt_Hash_Incremental_finish_blake2s, EverCrypt_Hash_Incremental_finish_blake2b, EverCrypt_Hash_Incremental_alg_of_state, EverCrypt_Hash_Incremental_finish, EverCrypt_Hash_Incremental_free -->

```{doxygenfunction} EverCrypt_Hash_hash
```

`a` Algorithm to use.
`dst` Pointer to digest.
`input` Pointer to message.
`len` Length of message.

--------------------------------------------------------------------------------

```{doxygenfunction} EverCrypt_Hash_Incremental_create_in
```

Create a hash state.

`a` Algorithm to use.

```{doxygenfunction} EverCrypt_Hash_Incremental_init
```

Initialize hash state).

`s` The hash state.

```{doxygenfunction} EverCrypt_Hash_Incremental_update
```

Feed the next chunk of the message that will be hashed.

`p` The hash state.
`data` Pointer to the next chunk of the message that will be hashed.
`len` Length of the next chunk of the message that will be hashed.

```{doxygenfunction} EverCrypt_Hash_Incremental_finish
```

Finish the hash calculation and write the digest to `dst`.

`s` The hash state.
`dst` Pointer to digest.

```{doxygenfunction} EverCrypt_Hash_Incremental_free
```

Cleanup the hash state.

`s` The hash state.

--------------------------------------------------------------------------------

```{doxygenfunction} EverCrypt_Hash_string_of_alg
```

```{doxygenfunction} EverCrypt_Hash_uu___is_MD5_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_SHA1_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_SHA2_224_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_SHA2_256_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_SHA2_384_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_SHA2_512_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_Blake2S_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_Blake2S_128_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_Blake2B_s
```

```{doxygenfunction} EverCrypt_Hash_uu___is_Blake2B_256_s
```

```{doxygenfunction} EverCrypt_Hash_alg_of_state
```

```{doxygenfunction} EverCrypt_Hash_create_in
```

```{doxygenfunction} EverCrypt_Hash_create
```

```{doxygenfunction} EverCrypt_Hash_init
```

```{doxygenfunction} EverCrypt_Hash_update_multi_256
```

```{doxygenfunction} EverCrypt_Hash_update2
```

```{doxygenfunction} EverCrypt_Hash_update
```

```{doxygenfunction} EverCrypt_Hash_update_multi2
```

```{doxygenfunction} EverCrypt_Hash_update_multi
```

```{doxygenfunction} EverCrypt_Hash_update_last_256
```

```{doxygenfunction} EverCrypt_Hash_update_last2
```

```{doxygenfunction} EverCrypt_Hash_update_last
```

```{doxygenfunction} EverCrypt_Hash_finish
```

```{doxygenfunction} EverCrypt_Hash_free
```

```{doxygenfunction} EverCrypt_Hash_copy
```

```{doxygenfunction} EverCrypt_Hash_hash_256
```

```{doxygenfunction} EverCrypt_Hash_hash_224
```

```{doxygenfunction} EverCrypt_Hash_Incremental_hash_len
```

```{doxygenfunction} EverCrypt_Hash_Incremental_block_len
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_md5
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_sha1
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_sha224
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_sha256
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_sha384
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_sha512
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_blake2s
```

```{doxygenfunction} EverCrypt_Hash_Incremental_finish_blake2b
```

```{doxygenfunction} EverCrypt_Hash_Incremental_alg_of_state
```

