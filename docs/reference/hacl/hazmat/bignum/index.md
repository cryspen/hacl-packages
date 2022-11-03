# Bignum

HACL's bignum library comes in multiple variants and specializations.

|                 | 32-Bit                 | 64-Bit              |
|-----------------|------------------------|---------------------|
| Generic         | `Hacl_Bignum32.h`      | `Hacl_Bignum64.h`   |
| 256-Bit Bignum  | `Hacl_Bignum256_32.h`  | `Hacl_Bignum256.h`  |
| 4096-Bit Bignum | `Hacl_Bignum4096_32.h` | `Hacl_Bignum4096.h` |

Additional headers: `Hacl_Bignum_Base.h`, `Hacl_Bignum.h`, `Hacl_Bignum25519_51.h`, `Hacl_Bignum_K256.h`.

## API Reference

```````{tabs}
``````{group-tab} 32
`````{tabs}
````{group-tab} General-Purpose
```C
#include "Hacl_Bignum32.h"
```
````
````{group-tab} Specialized to 256-Bit Integers
```C
#include "Hacl_Bignum256_32.h"
```
````
````{group-tab} Specialized to 4096-Bit Integers
```C
#include "Hacl_Bignum4096_32.h"
```
````
`````
``````
``````{group-tab} 64
`````{tabs}
````{group-tab} General-Purpose
```C
#include "Hacl_Bignum64.h"
```
````
````{group-tab} Specialized to 256-Bit Integers
```C
#include "Hacl_Bignum256.h"
```
````
````{group-tab} Specialized to 4096-Bit Integers
```C
#include "Hacl_Bignum4096.h"
```
````
`````
``````
```````

### Loads and stores

```````{tabs}
``````{group-tab} 32
`````{tabs}
````{group-tab} General-Purpose
```{doxygenfunction} Hacl_Bignum32_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum32_new_bn_from_bytes_le
```

```{doxygenfunction} Hacl_Bignum32_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum32_bn_to_bytes_le
```
````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_32_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum256_32_new_bn_from_bytes_le
```

```{doxygenfunction} Hacl_Bignum256_32_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum256_32_bn_to_bytes_le
```
````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_32_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum4096_32_new_bn_from_bytes_le
```

```{doxygenfunction} Hacl_Bignum4096_32_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum4096_32_bn_to_bytes_le
```
````
`````
``````
``````{group-tab} 64
`````{tabs}
````{group-tab} General-Purpose
```{doxygenfunction} Hacl_Bignum64_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum64_new_bn_from_bytes_le
```

```{doxygenfunction} Hacl_Bignum64_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum64_bn_to_bytes_le
```
````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum256_new_bn_from_bytes_le
```

```{doxygenfunction} Hacl_Bignum256_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum256_bn_to_bytes_le
```
````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum4096_new_bn_from_bytes_le
```

```{doxygenfunction} Hacl_Bignum4096_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum4096_bn_to_bytes_le
```
````
`````
``````
```````

### Arithmetic functions

```````{tabs}
``````{group-tab} 32
`````{tabs}
````{group-tab} General-Purpose
```{doxygenfunction} Hacl_Bignum32_add
```

```{doxygenfunction} Hacl_Bignum32_add_mod
```

```{doxygenfunction} Hacl_Bignum32_sub
```

```{doxygenfunction} Hacl_Bignum32_sub_mod
```

```{doxygenfunction} Hacl_Bignum32_mul
```

```{doxygenfunction} Hacl_Bignum32_sqr
```

```{doxygenfunction} Hacl_Bignum32_mod
```

```{doxygenfunction} Hacl_Bignum32_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum32_mod_exp_vartime
```

```{doxygenfunction} Hacl_Bignum32_mod_inv_prime_vartime
```

Note: There is no `mod_inv_prime_consttime` version.

````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_32_add
```

```{doxygenfunction} Hacl_Bignum256_32_add_mod
```

```{doxygenfunction} Hacl_Bignum256_32_sub
```

```{doxygenfunction} Hacl_Bignum256_32_sub_mod
```

```{doxygenfunction} Hacl_Bignum256_32_mul
```

```{doxygenfunction} Hacl_Bignum256_32_sqr
```

```{doxygenfunction} Hacl_Bignum256_32_mod
```

```{doxygenfunction} Hacl_Bignum256_32_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum256_32_mod_exp_vartime
```

```{doxygenfunction} Hacl_Bignum256_32_mod_inv_prime_vartime
```

Note: There is no `mod_inv_prime_consttime` version.

````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_32_add
```

```{doxygenfunction} Hacl_Bignum4096_32_add_mod
```

```{doxygenfunction} Hacl_Bignum4096_32_sub
```

```{doxygenfunction} Hacl_Bignum4096_32_sub_mod
```

```{doxygenfunction} Hacl_Bignum4096_32_mul
```

```{doxygenfunction} Hacl_Bignum4096_32_sqr
```

```{doxygenfunction} Hacl_Bignum4096_32_mod
```

```{doxygenfunction} Hacl_Bignum4096_32_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum4096_32_mod_exp_vartime
```

```{doxygenfunction} Hacl_Bignum4096_32_mod_inv_prime_vartime
```

Note: There is no `mod_inv_prime_consttime` version.

````
`````
``````
``````{group-tab} 64
`````{tabs}
````{group-tab} General-Purpose
```{doxygenfunction} Hacl_Bignum64_add
```

```{doxygenfunction} Hacl_Bignum64_add_mod
```

```{doxygenfunction} Hacl_Bignum64_sub
```

```{doxygenfunction} Hacl_Bignum64_sub_mod
```

```{doxygenfunction} Hacl_Bignum64_mul
```

```{doxygenfunction} Hacl_Bignum64_sqr
```

```{doxygenfunction} Hacl_Bignum64_mod
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_vartime
```

```{doxygenfunction} Hacl_Bignum64_mod_inv_prime_vartime
```

Note: There is no `mod_inv_prime_consttime` version.
````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_add
```

```{doxygenfunction} Hacl_Bignum256_add_mod
```

```{doxygenfunction} Hacl_Bignum256_sub
```

```{doxygenfunction} Hacl_Bignum256_sub_mod
```

```{doxygenfunction} Hacl_Bignum256_mul
```

```{doxygenfunction} Hacl_Bignum256_sqr
```

```{doxygenfunction} Hacl_Bignum256_mod
```

```{doxygenfunction} Hacl_Bignum256_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum256_mod_exp_vartime
```

```{doxygenfunction} Hacl_Bignum256_mod_inv_prime_vartime
```

Note: There is no `mod_inv_prime_consttime` version.
````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_add
```

```{doxygenfunction} Hacl_Bignum4096_add_mod
```

```{doxygenfunction} Hacl_Bignum4096_sub
```

```{doxygenfunction} Hacl_Bignum4096_sub_mod
```

```{doxygenfunction} Hacl_Bignum4096_mul
```

```{doxygenfunction} Hacl_Bignum4096_sqr
```

```{doxygenfunction} Hacl_Bignum4096_mod
```

```{doxygenfunction} Hacl_Bignum4096_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum4096_mod_exp_vartime
```

```{doxygenfunction} Hacl_Bignum4096_mod_inv_prime_vartime
```

Note: There is no `mod_inv_prime_consttime` version.
````
`````
``````
```````

### Comparisons

```````{tabs}
``````{group-tab} 32
`````{tabs}
````{group-tab} General-Purpose
```{doxygenfunction} Hacl_Bignum32_lt_mask
```

```{doxygenfunction} Hacl_Bignum32_eq_mask
```
````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_32_lt_mask
```

```{doxygenfunction} Hacl_Bignum256_32_eq_mask
```
````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_32_lt_mask
```

```{doxygenfunction} Hacl_Bignum4096_32_eq_mask
```
````
`````
``````
``````{group-tab} 64
`````{tabs}
````{group-tab} General-Purpose
```{doxygenfunction} Hacl_Bignum64_lt_mask
```

```{doxygenfunction} Hacl_Bignum64_eq_mask
```
````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_lt_mask
```

```{doxygenfunction} Hacl_Bignum256_eq_mask
```
````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_lt_mask
```

```{doxygenfunction} Hacl_Bignum4096_eq_mask
```
````
`````
``````
```````






### Arithmetic functions with precomputations

```````{tabs}
``````{group-tab} 32
```{doxygentypedef} Hacl_Bignum32_pbn_mont_ctx_u32
```
`````{tabs}
````{group-tab} General-Purpose

```{doxygenfunction} Hacl_Bignum32_mont_ctx_init
```

```{doxygenfunction} Hacl_Bignum32_mont_ctx_free
```

```{doxygenfunction} Hacl_Bignum32_mod_precomp
```

```{doxygenfunction} Hacl_Bignum32_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum32_mod_exp_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum32_mod_inv_prime_vartime_precomp
```
````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_32_mont_ctx_init
```

```{doxygenfunction} Hacl_Bignum256_32_mont_ctx_free
```

```{doxygenfunction} Hacl_Bignum256_32_mod_precomp
```

```{doxygenfunction} Hacl_Bignum256_32_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum256_32_mod_exp_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum256_32_mod_inv_prime_vartime_precomp
```
````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_32_mont_ctx_init
```

```{doxygenfunction} Hacl_Bignum4096_32_mont_ctx_free
```

```{doxygenfunction} Hacl_Bignum4096_32_mod_precomp
```

```{doxygenfunction} Hacl_Bignum4096_32_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum4096_32_mod_exp_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum4096_32_mod_inv_prime_vartime_precomp
```
````
`````
``````
``````{group-tab} 64
```{doxygentypedef} Hacl_Bignum64_pbn_mont_ctx_u64
```
`````{tabs}
````{group-tab} General-Purpose
```{doxygenfunction} Hacl_Bignum64_mont_ctx_init
```

```{doxygenfunction} Hacl_Bignum64_mont_ctx_free
```

```{doxygenfunction} Hacl_Bignum64_mod_precomp
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum64_mod_inv_prime_vartime_precomp
```
````
````{group-tab} Specialized to 256-Bit Integers
```{doxygenfunction} Hacl_Bignum256_mont_ctx_init
```

```{doxygenfunction} Hacl_Bignum256_mont_ctx_free
```

```{doxygenfunction} Hacl_Bignum256_mod_precomp
```

```{doxygenfunction} Hacl_Bignum256_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum256_mod_exp_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum256_mod_inv_prime_vartime_precomp
```
````
````{group-tab} Specialized to 4096-Bit Integers
```{doxygenfunction} Hacl_Bignum4096_mont_ctx_init
```

```{doxygenfunction} Hacl_Bignum4096_mont_ctx_free
```

```{doxygenfunction} Hacl_Bignum4096_mod_precomp
```

```{doxygenfunction} Hacl_Bignum4096_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum4096_mod_exp_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum4096_mod_inv_prime_vartime_precomp
```
````
`````
``````
```````

