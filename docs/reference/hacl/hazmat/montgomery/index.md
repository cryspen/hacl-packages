# Montgomery Field Arithmetic

A verified Montgomery field arithmetic library.

HACL Packages comes with two versions, a 32-bit optimized version, where bignums are represented as an array of `len` unsigned 32-bit integers, i.e., `uint32_t[len]` and a 64-bit optimized version.

All the arithmetic operations are performed in the Montgomery domain and preserve the invariant that `aM < n` for a bignum `aM` in Montgomery form.

## API Reference

`````{tabs}
````{group-tab} 32
```C
#include "Hacl_GenericField32.h"
```
````
````{group-tab} 64
```C
#include "Hacl_GenericField64.h"
```
````
`````

### Typedefs

`````{tabs}
````{group-tab} 32
```{doxygentypedef} Hacl_GenericField32_pbn_mont_ctx_u32
```
````
````{group-tab} 64
```{doxygentypedef} Hacl_GenericField64_pbn_mont_ctx_u64
```
````
`````

### Functions

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_GenericField32_field_modulus_check
```

```{doxygenfunction} Hacl_GenericField32_field_init
```

```{doxygenfunction} Hacl_GenericField32_field_free
```

```{doxygenfunction} Hacl_GenericField32_field_get_len
```

```{doxygenfunction} Hacl_GenericField32_to_field
```

```{doxygenfunction} Hacl_GenericField32_from_field
```

```{doxygenfunction} Hacl_GenericField32_add
```

```{doxygenfunction} Hacl_GenericField32_sub
```

```{doxygenfunction} Hacl_GenericField32_mul
```

```{doxygenfunction} Hacl_GenericField32_sqr
```

```{doxygenfunction} Hacl_GenericField32_one
```

```{doxygenfunction} Hacl_GenericField32_exp_consttime
```

```{doxygenfunction} Hacl_GenericField32_exp_vartime
```

```{doxygenfunction} Hacl_GenericField32_inverse
```
````
````{group-tab} 64
```{doxygenfunction} Hacl_GenericField64_field_modulus_check
```

```{doxygenfunction} Hacl_GenericField64_field_init
```

```{doxygenfunction} Hacl_GenericField64_field_free
```

```{doxygenfunction} Hacl_GenericField64_field_get_len
```

```{doxygenfunction} Hacl_GenericField64_to_field
```

```{doxygenfunction} Hacl_GenericField64_from_field
```

```{doxygenfunction} Hacl_GenericField64_add
```

```{doxygenfunction} Hacl_GenericField64_sub
```

```{doxygenfunction} Hacl_GenericField64_mul
```

```{doxygenfunction} Hacl_GenericField64_sqr
```

```{doxygenfunction} Hacl_GenericField64_one
```

```{doxygenfunction} Hacl_GenericField64_exp_consttime
```

```{doxygenfunction} Hacl_GenericField64_exp_vartime
```

```{doxygenfunction} Hacl_GenericField64_inverse
```
````
`````

