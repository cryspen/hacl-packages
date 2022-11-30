# Randomness

## DRBG

Deterministic Random Bit Generator (DRBG) (NIST, SP 800-90A).

### Available Implementations

```C
#include "Hacl_HMAC_DRBG.h"
```

### API Reference

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

Create a DRBG state.

* `a` Hash algorithm to use. The possible instantiations are ...

* `Spec_Hash_Definitions_SHA2_256`,
* `Spec_Hash_Definitions_SHA2_384`,
* `Spec_Hash_Definitions_SHA2_512`, and
* `Spec_Hash_Definitions_SHA1`.

<!--
```{doxygenfunction} Hacl_HMAC_DRBG_uu___is_State
```
-->

```{doxygenfunction} Hacl_HMAC_DRBG_instantiate
```

Instantiate the DRBG.

* `a` Hash algorithm to use. (Value must match the value used in `Hacl_HMAC_DRBG_create_in`.)
* `st` Pointer to DRBG state.
* `entropy_input_len` Length of entropy input.
* `entropy_input` Pointer to `entropy_input_len` bytes of memory where entropy input is read from.
* `nonce_len` Length of nonce.
* `nonce` Pointer to `nonce_len` bytes of memory where nonce is read from.
* `personalization_string_len` length of personalization string.
* `personalization_string` Pointer to `personalization_string_len` bytes of memory where personalization string is read from.

```{doxygenfunction} Hacl_HMAC_DRBG_reseed
```

Reseed the DRBG.

* `a` Hash algorithm to use. (Value must match the value used in `Hacl_HMAC_DRBG_create_in`.)
* `st` Pointer to DRBG state.
* `entropy_input_len` Length of entropy input.
* `entropy_input` Pointer to `entropy_input_len` bytes of memory where entropy input is read from.
* `additional_input_input_len` Length of additional input.
* `additional_input_input` Pointer to `additional_input_input_len` bytes of memory where additional input is read from.

```{doxygenfunction} Hacl_HMAC_DRBG_generate
```

Generate output.

* `a` Hash algorithm to use. (Value must match the value used in `Hacl_HMAC_DRBG_create_in`.)
* `output` Pointer to `n` bytes of memory where random output is written to.
* `st` Pointer to DRBG state.
* `n` Length of desired output.
* `additional_input_input_len` Length of additional input.
* `additional_input_input` Pointer to `additional_input_input_len` bytes of memory where additional input is read from.

<!--
```{doxygenfunction} Hacl_HMAC_DRBG_free
```
-->

````{warning}
**Cleanup and free the DRBG state.**

Currently, there is no free function available. You can use ...

```C
void free_state(Hacl_HMAC_DRBG_state* state)
{
  KRML_HOST_FREE(state->k);
  KRML_HOST_FREE(state->reseed_counter);
  KRML_HOST_FREE(state->v);
}
```

... to cleanup the state.

````

```{doxygenfunction} Hacl_HMAC_DRBG_min_length
```

Return the minimal entropy input length of the desired hash function.

* `a` Hash algorithm to use.

