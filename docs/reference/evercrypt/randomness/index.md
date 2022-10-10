# Randomness

## DRBG

Deterministic Random Bit Generator (DRBG) (NIST, SP 800-90A).

### API Reference

```C
#include "EverCrypt_DRBG.h"
```

#### Variables

```{doxygenvariable} EverCrypt_DRBG_reseed_interval
```

```{doxygenvariable} EverCrypt_DRBG_max_output_length
```

```{doxygenvariable} EverCrypt_DRBG_max_length
```

```{doxygenvariable} EverCrypt_DRBG_max_personalization_string_length
```

```{doxygenvariable} EverCrypt_DRBG_max_additional_input_length
```

#### Typedefs

```{doxygentypedef} EverCrypt_DRBG_supported_alg
```

```{doxygentypedef} EverCrypt_DRBG_state_s
```


#### Functions

```{doxygenfunction} EverCrypt_DRBG_create
```

Create a DRBG state.

* `a` Hash algorithm to use. The possible instantiations are ...

* `Spec_Hash_Definitions_SHA2_256`,
* `Spec_Hash_Definitions_SHA2_384`,
* `Spec_Hash_Definitions_SHA2_512`, and
* `Spec_Hash_Definitions_SHA1`.

```{doxygenfunction} EverCrypt_DRBG_instantiate
```

Instantiate the DRBG.

* `st` Pointer to DRBG state.
* `personalization_string_len` length of personalization string.
* `personalization_string` Pointer to `personalization_string_len` bytes of memory where personalization string is read from.

<!-- Note: entropy_input is generated. No nonce? -->

```{doxygenfunction} EverCrypt_DRBG_reseed
```

Reseed the DRBG.

* `st` Pointer to DRBG state.
* `additional_input_input_len` Length of additional input.
* `additional_input_input` Pointer to `additional_input_input_len` bytes of memory where additional input is read from.

```{doxygenfunction} EverCrypt_DRBG_generate
```

Generate output.

* `output` Pointer to `n` bytes of memory where random output is written to.
* `st` Pointer to DRBG state.
* `n` Length of desired output.
* `additional_input_input_len` Length of additional input.
* `additional_input_input` Pointer to `additional_input_input_len` bytes of memory where additional input is read from.

```{doxygenfunction} EverCrypt_DRBG_uninstantiate
```

Uninstantiate and free the DRBG.

* `st` Pointer to DRBG state.

```{doxygenfunction} EverCrypt_DRBG_min_length
```

--------------------------------------------------------------------------------

```{doxygenfunction} EverCrypt_DRBG_uu___is_SHA1_s
```

```{doxygenfunction} EverCrypt_DRBG_uu___is_SHA2_256_s
```

```{doxygenfunction} EverCrypt_DRBG_uu___is_SHA2_384_s
```

```{doxygenfunction} EverCrypt_DRBG_uu___is_SHA2_512_s
```

```{doxygenfunction} EverCrypt_DRBG_instantiate_sha1
```

```{doxygenfunction} EverCrypt_DRBG_instantiate_sha2_256
```

```{doxygenfunction} EverCrypt_DRBG_instantiate_sha2_384
```

```{doxygenfunction} EverCrypt_DRBG_instantiate_sha2_512
```

```{doxygenfunction} EverCrypt_DRBG_reseed_sha1
```

```{doxygenfunction} EverCrypt_DRBG_reseed_sha2_256
```

```{doxygenfunction} EverCrypt_DRBG_reseed_sha2_384
```

```{doxygenfunction} EverCrypt_DRBG_reseed_sha2_512
```

```{doxygenfunction} EverCrypt_DRBG_generate_sha1
```

```{doxygenfunction} EverCrypt_DRBG_generate_sha2_256
```

```{doxygenfunction} EverCrypt_DRBG_generate_sha2_384
```

```{doxygenfunction} EverCrypt_DRBG_generate_sha2_512
```

```{doxygenfunction} EverCrypt_DRBG_uninstantiate_sha1
```

```{doxygenfunction} EverCrypt_DRBG_uninstantiate_sha2_256
```

```{doxygenfunction} EverCrypt_DRBG_uninstantiate_sha2_384
```

```{doxygenfunction} EverCrypt_DRBG_uninstantiate_sha2_512
```

