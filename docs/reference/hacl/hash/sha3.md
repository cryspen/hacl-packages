# SHA-3

SHA-3 comes in six different variants (instantiations) ...

* SHA3-224,
* SHA3-256,	
* SHA3-384,
* SHA3-512,
* SHAKE128, and
* SHAKE256.

The number in `SHA3-*` denotes the digest size, i.e., how many *bits* are produced by the hash function.
SHAKE128 and SHAKE256 have a 128- or 256-bit security strength and can produce as many bytes as requested.

## API Reference

### One-Shot

**Example**

```{literalinclude} ../../../../tests/sha3.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define)"
:end-before: "// ANCHOR_END(example define)"
```

```{literalinclude} ../../../../tests/sha3.cc
:language: C
:dedent:
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

`````{tabs}
````{tab} 28 byte digest
```{doxygenfunction} Hacl_SHA3_sha3_224
```
````

````{tab} 32 byte digest
```{doxygenfunction} Hacl_SHA3_sha3_256
```
````

````{tab} 48 byte digest
```{doxygenfunction} Hacl_SHA3_sha3_384
```
````

````{tab} 64 byte digest
```{doxygenfunction} Hacl_SHA3_sha3_512
```
````
`````

### Streaming

**Example**

```{literalinclude} ../../../../tests/sha3.cc
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

```{literalinclude} ../../../../tests/sha3.cc
:language: C
:dedent:
:start-after: "// ANCHOR(streaming)"
:end-before: "// ANCHOR_END(streaming)"
```

```{doxygentypedef} Hacl_Streaming_SHA3_state_sha3_256
```

```{doxygenfunction} Hacl_Streaming_SHA3_create_in_256
```

```{doxygenfunction} Hacl_Streaming_SHA3_init_256
```

```{doxygenfunction} Hacl_Streaming_SHA3_update_256
```

```{doxygenfunction} Hacl_Streaming_SHA3_finish_256
```

```{doxygenfunction} Hacl_Streaming_SHA3_free_256
```

## SHAKE

### API Reference

#### One-Shot

**Example**

```{literalinclude} ../../../../tests/sha3.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example shake128)"
:end-before: "// ANCHOR_END(example shake128)"
```

`````{tabs}
````{tab} 128-bit security strength
```{doxygenfunction} Hacl_SHA3_shake128_hacl
```
````

````{tab} 256-bit security strength
```{doxygenfunction} Hacl_SHA3_shake256_hacl
```
````
`````

#### Streaming

No streaming API available.

