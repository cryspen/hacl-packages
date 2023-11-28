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

**Example**

```{literalinclude} ../../../../tests/sha2.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define)"
:end-before: "// ANCHOR_END(example define)"
```

```{literalinclude} ../../../../tests/sha2.cc
:language: C
:dedent:
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

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

### Streaming

**Example**

```{literalinclude} ../../../../tests/sha2.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define)"
:end-before: "// ANCHOR_END(example define)"
```

```{literalinclude} ../../../../tests/util.h
:language: C
:dedent:
:start-after: "// ANCHOR(print_hex_ln)"
:end-before: "// ANCHOR_END(print_hex_ln)"
```

```{literalinclude} ../../../../tests/sha2.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example streaming)"
:end-before: "// ANCHOR_END(example streaming)"
```

`````{tabs}
````{group-tab} 28 byte digest

**Init**

```{doxygentypedef} Hacl_Hash_SHA2_state_t_224
```

```{doxygenfunction} Hacl_Hash_SHA2_malloc_224
```

**Update**

```{doxygenfunction} Hacl_Hash_SHA2_update_224
```

**Finish**

```{doxygenfunction} Hacl_Hash_SHA2_digest_224
```

```{doxygenfunction} Hacl_Hash_SHA2_reset_224
```

```{doxygenfunction} Hacl_Hash_SHA2_free_224
```
````

````{group-tab} 32 byte digest

**Init**

```{doxygentypedef} Hacl_Hash_SHA2_state_t_256
```

```{doxygenfunction} Hacl_Hash_SHA2_malloc_256
```

**Update**

```{doxygenfunction} Hacl_Hash_SHA2_update_256
```

**Finish**

```{doxygenfunction} Hacl_Hash_SHA2_digest_256
```

```{doxygenfunction} Hacl_Hash_SHA2_reset_256
```

```{doxygenfunction} Hacl_Hash_SHA2_free_256
```
````

````{group-tab} 48 byte digest

**Init**

```{doxygentypedef} Hacl_Hash_SHA2_state_t_384
```

```{doxygenfunction} Hacl_Hash_SHA2_malloc_384
```

**Update**

```{doxygenfunction} Hacl_Hash_SHA2_update_384
```

**Finish**

```{doxygenfunction} Hacl_Hash_SHA2_digest_384
```

```{doxygenfunction} Hacl_Hash_SHA2_reset_384
```

```{doxygenfunction} Hacl_Hash_SHA2_free_384
```
````


````{group-tab} 64 byte digest

**Init**

```{doxygentypedef} Hacl_Hash_SHA2_state_t_512
```

```{doxygenfunction} Hacl_Hash_SHA2_malloc_512
```

**Update**

```{doxygenfunction} Hacl_Hash_SHA2_update_512
```

**Finish**

```{doxygenfunction} Hacl_Hash_SHA2_digest_512
```

```{doxygenfunction} Hacl_Hash_SHA2_reset_512
```

```{doxygenfunction} Hacl_Hash_SHA2_free_512
```
````
`````

