# Blake2b

BLAKE2b is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes.
It also has a build-in keying mechanism so that it can be used to replace HMAC-based constructions.

## API Reference

### One-Shot


`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2b_32_blake2b
```

````

````{group-tab} 256

```{doxygenfunction} Hacl_Blake2b_256_blake2b
```

````
`````

### Streaming

```{doxygentypedef} Hacl_Impl_Blake2_Core_m_spec
```

--------------------------------------------------------------------------------

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2b_32_blake2b_init
```

````

````{group-tab} 256

```{doxygenfunction} Hacl_Blake2b_256_blake2b_init
```

````
`````

--------------------------------------------------------------------------------

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2b_32_blake2b_update_key
```

```{doxygenfunction} Hacl_Blake2b_32_blake2b_update_multi
```

```{doxygenfunction} Hacl_Blake2b_32_blake2b_update_last
```

````

````{group-tab} 256

```{doxygenfunction} Hacl_Blake2b_256_blake2b_update_key
```

```{doxygenfunction} Hacl_Blake2b_256_blake2b_update_multi
```

```{doxygenfunction} Hacl_Blake2b_256_blake2b_update_last
```

````
`````

--------------------------------------------------------------------------------

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2b_32_blake2b_finish
```

````

````{group-tab} 256

```{doxygenfunction} Hacl_Blake2b_256_blake2b_finish
```

````
`````

### Compatibility

```{doxygenfunction} Hacl_Blake2b_256_load_state256b_from_state32
```

```{doxygenfunction} Hacl_Blake2b_256_store_state256b_to_state32
```

