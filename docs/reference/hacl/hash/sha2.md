# SHA-2

SHA-2 comes in six different variants (instantiations) ...

* SHA-224,
* SHA-256,
* SHA-384,
* SHA-512,
* SHA-512/224 (not supported by HACL), and
* SHA-512/256 (not supported by HACL).

The number denotes the digest size, i.e., how many *bits* are produced by the hash function.

Note: While `SHA-256` already denotes the hash function from the SHA-2 family that produces 256 bits of output,
it is sometimes called `SHA2-256` to avoid confusion with SHA-1 and SHA-3.

## API Reference

### One-Shot

`````{tabs}
````{group-tab} 28 byte digest
```{doxygenfunction} Hacl_Hash_SHA2_hash_224
```
````

````{group-tab} 32 byte digest
```{doxygenfunction} Hacl_Hash_SHA2_hash_256
```
````

````{group-tab} 48 byte digest
```{doxygenfunction} Hacl_Hash_SHA2_hash_384
```
````

````{group-tab} 64 byte digest
```{doxygenfunction} Hacl_Hash_SHA2_hash_512
```
````
`````

**Example**

This is an example how to use the SHA-2 one-shot API to digest a complete message.

The digest is written to the memory pointed to by digest and the caller is expected to allocate enough memory for the digest.

```{literalinclude} ../../../../tests/sha2.cc
:language: C
:dedent:
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

### Streaming

`````{tabs}
````{group-tab} 28 byte digest

**Init**

```{doxygentypedef} Hacl_Streaming_SHA2_state_sha2_224
```

```{doxygenfunction} Hacl_Streaming_SHA2_create_in_224
```

```{doxygenfunction} Hacl_Streaming_SHA2_init_224
```

**Update**

```{doxygenfunction} Hacl_Streaming_SHA2_update_224
```

**Finish**

```{doxygenfunction} Hacl_Streaming_SHA2_finish_224
```

```{doxygenfunction} Hacl_Streaming_SHA2_free_224
```
````

````{group-tab} 32 byte digest

**Init**

```{doxygentypedef} Hacl_Streaming_SHA2_state_sha2_256
```

```{doxygenfunction} Hacl_Streaming_SHA2_create_in_256
```

```{doxygenfunction} Hacl_Streaming_SHA2_init_256
```

**Update**

```{doxygenfunction} Hacl_Streaming_SHA2_update_256
```

**Finish**

```{doxygenfunction} Hacl_Streaming_SHA2_finish_256
```

```{doxygenfunction} Hacl_Streaming_SHA2_free_256
```
````

````{group-tab} 48 byte digest

**Init**

```{doxygentypedef} Hacl_Streaming_SHA2_state_sha2_384
```

```{doxygenfunction} Hacl_Streaming_SHA2_create_in_384
```

```{doxygenfunction} Hacl_Streaming_SHA2_init_384
```

**Update**

```{doxygenfunction} Hacl_Streaming_SHA2_update_384
```

**Finish**

```{doxygenfunction} Hacl_Streaming_SHA2_finish_384
```

```{doxygenfunction} Hacl_Streaming_SHA2_free_384
```
````


````{group-tab} 64 byte digest

**Init**

```{doxygentypedef} Hacl_Streaming_SHA2_state_sha2_512
```

```{doxygenfunction} Hacl_Streaming_SHA2_create_in_512
```

```{doxygenfunction} Hacl_Streaming_SHA2_init_512
```

**Update**

```{doxygenfunction} Hacl_Streaming_SHA2_update_512
```

**Finish**

```{doxygenfunction} Hacl_Streaming_SHA2_finish_512
```

```{doxygenfunction} Hacl_Streaming_SHA2_free_512
```
````
`````

**Example**

```{literalinclude} ../../../../tests/sha2.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example streaming)"
:end-before: "// ANCHOR_END(example streaming)"
```


