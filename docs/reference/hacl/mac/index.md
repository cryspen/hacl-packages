# MAC

## HMAC

### API Reference

#### BLAKE2b


`````{tabs}

````{tab} 32

```{doxygenfunction} Hacl_HMAC_compute_blake2b_32
```

````

````{tab} 256

```{doxygenfunction} Hacl_HMAC_Blake2b_256_compute_blake2b_256
```

````
`````

#### BLAKE2s

`````{tabs}

````{tab} 32

```{doxygenfunction} Hacl_HMAC_compute_blake2s_32
```

````

````{tab} 128

```{doxygenfunction} Hacl_HMAC_Blake2s_128_compute_blake2s_128
```

````
`````

#### SHA-2

```{doxygenfunction} Hacl_HMAC_compute_sha2_256
```

```{doxygenfunction} Hacl_HMAC_compute_sha2_384
```

```{doxygenfunction} Hacl_HMAC_compute_sha2_512
```

#### SHA-1

```{doxygenfunction} Hacl_HMAC_legacy_compute_sha1
```

