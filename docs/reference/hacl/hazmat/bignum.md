# Bignum

HACL's bignum library comes in multiple variants and specializations.

|                 | 32-Bit             | 64-Bit          |
|-----------------|--------------------|-----------------|
| Generic         | Hacl_Bignum32.h    | Hacl_Bignum64.h |
| 256-Bit Bignum  | ...                | ...             |
| 4096-Bit Bignum | ...                | ...             |

## API Reference

### Loads and stores

```{doxygenfunction} Hacl_Bignum32_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum32_new_bn_from_bytes_le
```

```{doxygenfunction} Hacl_Bignum64_new_bn_from_bytes_be
```

```{doxygenfunction} Hacl_Bignum64_new_bn_from_bytes_le
```

**Example**

```c
```

### Arithmetic functions

```{doxygenfunction} Hacl_Bignum32_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum32_bn_to_bytes_le
```

```{doxygenfunction} Hacl_Bignum64_bn_to_bytes_be
```

```{doxygenfunction} Hacl_Bignum64_bn_to_bytes_le
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_add
```

```{doxygenfunction} Hacl_Bignum64_add
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_add_mod
```

```{doxygenfunction} Hacl_Bignum64_add_mod
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_sub
```

```{doxygenfunction} Hacl_Bignum64_sub
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_sub_mod
```

```{doxygenfunction} Hacl_Bignum64_sub_mod
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mul
```

```{doxygenfunction} Hacl_Bignum64_mul
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_sqr
```

```{doxygenfunction} Hacl_Bignum64_sqr
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mod
```

```{doxygenfunction} Hacl_Bignum64_mod
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum32_mod_exp_vartime
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_consttime
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_vartime
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mod_inv_prime_vartime
```

```{doxygenfunction} Hacl_Bignum64_mod_inv_prime_vartime
```

Note: There is no `_consttime` version.

**Example**

```c
```

-------------------------------------------------------------------------------

### Comparisons

```{doxygenfunction} Hacl_Bignum32_lt_mask
```

```{doxygenfunction} Hacl_Bignum32_eq_mask
```

```{doxygenfunction} Hacl_Bignum64_lt_mask
```

```{doxygenfunction} Hacl_Bignum64_eq_mask
```

**Example**

```c
```

### Arithmetic functions with precomputations

```{doxygentypedef} Hacl_Bignum32_pbn_mont_ctx_u32
```

```{doxygentypedef} Hacl_Bignum64_pbn_mont_ctx_u64
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mont_ctx_init
```

```{doxygenfunction} Hacl_Bignum64_mont_ctx_init
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mont_ctx_free
```

```{doxygenfunction} Hacl_Bignum64_mont_ctx_free
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mod_precomp
```

```{doxygenfunction} Hacl_Bignum64_mod_precomp

```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum32_mod_exp_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_consttime_precomp
```

```{doxygenfunction} Hacl_Bignum64_mod_exp_vartime_precomp
```

**Example**

```c
```

-------------------------------------------------------------------------------

```{doxygenfunction} Hacl_Bignum32_mod_inv_prime_vartime_precomp
```

```{doxygenfunction} Hacl_Bignum64_mod_inv_prime_vartime_precomp
```

Note: There is no `_consttime` version.

**Example**

```c
```
