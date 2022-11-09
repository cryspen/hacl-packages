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

**Example**

```{literalinclude} ../../../../tests/sha3.cc
:language: C
:dedent:
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

### Streaming

No streaming API available.

## SHAKE

### API Reference

#### One-Shot

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

**Example**

```{literalinclude} ../../../../tests/sha3.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example shake128)"
:end-before: "// ANCHOR_END(example shake128)"
```

#### Streaming

No streaming API available.

