# EdDSA

HACL Packages provides the Ed25519 instantiation of EdDSA, i.e., EdDSA signing and verification on the edwards25519 curve.

Two APIs are exposed: A (simple) "One-Shot" API to sign/verify a single message and a (more efficient) "Precomputed" API to sign multiple messages under the same (precomputed) key.

## API Reference

```{doxygenfunction} Hacl_Ed25519_secret_to_public
```

### One-Shot

```{doxygenfunction} Hacl_Ed25519_sign
```

```{doxygenfunction} Hacl_Ed25519_verify
```

**Example**

```{literalinclude} ../../../../tests/ed25519.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example)"
:end-before: "// ANCHOR_END(example)"
```

### Precomputed

```{doxygenfunction} Hacl_Ed25519_expand_keys
```

```{doxygenfunction} Hacl_Ed25519_sign_expanded
```

**Example**

```{literalinclude} ../../../../tests/ed25519.cc
:language: C
:dedent:
:start-after: "// ANCHOR(example precomputed)"
:end-before: "// ANCHOR_END(example precomputed)"
```
