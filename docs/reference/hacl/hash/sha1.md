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
:start-after: "// START OneShot"
:end-before: "// END OneShot"
```

```{doxygenfunction} Hacl_Hash_SHA1_legacy_hash
```

```{doxygenfunction} Hacl_Hash_SHA1_legacy_update_multi
```

```{doxygenfunction} Hacl_Hash_SHA1_legacy_update_last
```

### Streaming

**Example**

```{literalinclude} ../../../../tests/sha1.cc
:language: C
:dedent:
:start-after: "// ANCHOR(streaming)"
:end-before: "// ANCHOR_END(streaming)"
```

```{doxygentypedef} Hacl_Streaming_SHA1_state_sha1
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_create_in_sha1
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_init_sha1
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_update_sha1
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_finish_sha1
```

```{doxygenfunction} Hacl_Streaming_SHA1_legacy_free_sha1
```
