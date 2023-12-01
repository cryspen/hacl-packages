# SHA-1

```{warning}
SHA-1 is insecure. Please avoid or ask your cryptographer of trust for permission.
```

## API Reference

### One-Shot

**Example**

```{literalinclude} ../../../../tests/sha1.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example define)"
:end-before: "// ANCHOR_END(example define)"
```

```{literalinclude} ../../../../tests/sha1.cc
:language: C
:dedent:
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

```{doxygenfunction} Hacl_Hash_SHA1_hash
```

### Streaming

**Example**

```{literalinclude} ../../../../tests/sha1.cc
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

```{literalinclude} ../../../../tests/sha1.cc
:language: C
:dedent:
:start-after: "// ANCHOR(streaming)"
:end-before: "// ANCHOR_END(streaming)"
```

```{doxygentypedef} Hacl_Hash_SHA1_state_t
```

```{doxygenfunction} Hacl_Hash_SHA1_malloc
```

```{doxygenfunction} Hacl_Hash_SHA1_update
```

```{doxygenfunction} Hacl_Hash_SHA1_digest
```

```{doxygenfunction} Hacl_Hash_SHA1_reset
```

```{doxygenfunction} Hacl_Hash_SHA1_free
```
