# Randomness

## DRBG

Deterministic Random Bit Generator (DRBG) (NIST, SP 800-90A).

### Available Implementations

```C
#include "Hacl_HMAC_DRBG.h"
```

### API Reference

**Example**

```{literalinclude} ../../../../tests/drbg.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE)"
:end-before: "// ANCHOR_END(EXAMPLE)"
```

#### Variables

```{doxygenvariable} Hacl_HMAC_DRBG_reseed_interval
```

```{doxygenvariable} Hacl_HMAC_DRBG_max_output_length
```

```{doxygenvariable} Hacl_HMAC_DRBG_max_length
```

```{doxygenvariable} Hacl_HMAC_DRBG_max_personalization_string_length
```

```{doxygenvariable} Hacl_HMAC_DRBG_max_additional_input_length
```

#### Typedefs

```{doxygentypedef} Hacl_HMAC_DRBG_supported_alg
```

```{doxygentypedef} Hacl_HMAC_DRBG_state
```

#### Functions

```{doxygenfunction} Hacl_HMAC_DRBG_create_in
```

```{doxygenfunction} Hacl_HMAC_DRBG_instantiate
```

```{doxygenfunction} Hacl_HMAC_DRBG_reseed
```

```{doxygenfunction} Hacl_HMAC_DRBG_generate
```

```{doxygenfunction} Hacl_HMAC_DRBG_free
```

Free the DRBG state.

```{doxygenfunction} Hacl_HMAC_DRBG_min_length
```

