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

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_hash
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

```{doxygentypedef} Hacl_Streaming_SHA1_state
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_create_in
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_init
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_update
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_finish
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_free
```
