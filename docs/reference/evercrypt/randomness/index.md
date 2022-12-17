# Randomness

## DRBG

Deterministic Random Bit Generator (DRBG) (NIST, SP 800-90A).

## Available Implementations

```C
#include "EverCrypt_DRBG.h"
```

### API Reference

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

```{doxygenfunction} EverCrypt_DRBG_instantiate
```

<!-- Note: entropy_input is generated. No nonce? -->

```{doxygenfunction} EverCrypt_DRBG_reseed
```

```{doxygenfunction} EverCrypt_DRBG_generate
```

```{doxygenfunction} EverCrypt_DRBG_uninstantiate
```

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

