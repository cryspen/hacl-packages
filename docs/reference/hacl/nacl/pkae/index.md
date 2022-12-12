# Public-key Authenticated Encryption

Public-key authenticated encryption (Crypto Box).

This module provides a combined- and detached API with and without precomputation.
Please make sure that you use the correct pairs of functions to encrypt and decrypt messages as these APIs are not meant to be mixed.

Furthermore, NaCl supports in-place encryption/decryption.
Thus, the message and ciphertext are allowed to overlap.

## API Reference

### Combined mode

In combined mode, the authentication tag and encrypted message are stored consecutively in memory.
Thus, `c` must always point to memory with length 16 (tag length) + `mlen` (message length).

**Example**

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define box)"
:end-before: "// ANCHOR_END(example define box)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE SETUP)"
:end-before: "// ANCHOR_END(EXAMPLE SETUP)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE ONESHOT COMBINED)"
:end-before: "// ANCHOR_END(EXAMPLE ONESHOT COMBINED)"
```

```{doxygenfunction} Hacl_NaCl_crypto_box_easy
```

```{doxygenfunction} Hacl_NaCl_crypto_box_open_easy
```

### Detached mode

In detached mode, the authentication tag and encrypted message are stored separately.
Thus, `c` must always point to `mlen` bytes of memory and `tag` must always point to 16 (tag length) bytes of memory.

Note: NaCl supports in-place encryption/decryption.
Thus, the message and ciphertext are allowed to overlap.

**Example**

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define box)"
:end-before: "// ANCHOR_END(example define box)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE SETUP)"
:end-before: "// ANCHOR_END(EXAMPLE SETUP)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE ONESHOT DETACHED)"
:end-before: "// ANCHOR_END(EXAMPLE ONESHOT DETACHED)"
```

```{doxygenfunction} Hacl_NaCl_crypto_box_detached
```

```{doxygenfunction} Hacl_NaCl_crypto_box_open_detached
```

### With Precomputation

Applications that send several messages to the same recipient or receive several messages from the same sender can precompute a shared secret `k` once and reuse it in subsequent `_afternm` calls to increase performance.

```{doxygenfunction} Hacl_NaCl_crypto_box_beforenm
```

#### Combined mode

**Example**

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define box)"
:end-before: "// ANCHOR_END(example define box)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE SETUP)"
:end-before: "// ANCHOR_END(EXAMPLE SETUP)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE PRECOMPUTED COMBINED)"
:end-before: "// ANCHOR_END(EXAMPLE PRECOMPUTED COMBINED)"
```

```{doxygenfunction} Hacl_NaCl_crypto_box_easy_afternm
```

```{doxygenfunction} Hacl_NaCl_crypto_box_open_easy_afternm
```

#### Detached mode

**Example**

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define box)"
:end-before: "// ANCHOR_END(example define box)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE SETUP)"
:end-before: "// ANCHOR_END(EXAMPLE SETUP)"
```

```{literalinclude} ../../../../../tests/nacl.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE PRECOMPUTED DETACHED)"
:end-before: "// ANCHOR_END(EXAMPLE PRECOMPUTED DETACHED)"
```

```{doxygenfunction} Hacl_NaCl_crypto_box_detached_afternm
```

```{doxygenfunction} Hacl_NaCl_crypto_box_open_detached_afternm
```

