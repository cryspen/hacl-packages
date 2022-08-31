# KDF

## HKDF

### API Reference

#### BLAKE2b

`````{tabs}
````{tab} 32

```{doxygenfunction} Hacl_HKDF_expand_blake2b_32
```

```{doxygenfunction} Hacl_HKDF_expand_blake2b_32
```

````

````{tab} 256

```{doxygenfunction} Hacl_HKDF_Blake2b_256_expand_blake2b_256
```

```{doxygenfunction} Hacl_HKDF_Blake2b_256_extract_blake2b_256
```

````
`````

#### BLAKE2s

`````{tabs}
````{tab} 32

```{doxygenfunction} Hacl_HKDF_expand_blake2s_32
```

```{doxygenfunction} Hacl_HKDF_extract_blake2s_32
```

````

````{tab} 128

```{doxygenfunction} Hacl_HKDF_Blake2s_128_expand_blake2s_128
```

```{doxygenfunction} Hacl_HKDF_Blake2s_128_extract_blake2s_128
```

````
`````

#### SHA2-256

```{doxygenfunction} Hacl_HKDF_expand_sha2_256
```

```{doxygenfunction} Hacl_HKDF_extract_sha2_256
```

#### SHA2-512

```{doxygenfunction} Hacl_HKDF_expand_sha2_512
```

```{doxygenfunction} Hacl_HKDF_extract_sha2_512
```

