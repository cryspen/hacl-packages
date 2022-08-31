# Blake2s

BLAKE2s is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes.

## API Reference

### One-Shot

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2s_32_blake2s
```

````

````{group-tab} 128

```{doxygenfunction} Hacl_Blake2s_128_blake2s
```

````
`````

### Streaming

```{doxygentypedef} Hacl_Impl_Blake2_Core_m_spec
```

--------------------------------------------------------------------------------

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2s_32_blake2s_init
```

````

````{group-tab} 128

```{doxygenfunction} Hacl_Blake2s_128_blake2s_init
```

````
`````

--------------------------------------------------------------------------------

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2s_32_blake2s_update_key
```

```{doxygenfunction} Hacl_Blake2s_32_blake2s_update_multi
```

```{doxygenfunction} Hacl_Blake2s_32_blake2s_update_last
```

````

````{group-tab} 128

```{doxygenfunction} Hacl_Blake2s_128_blake2s_update_key
```

```{doxygenfunction} Hacl_Blake2s_128_blake2s_update_multi
```

```{doxygenfunction} Hacl_Blake2s_128_blake2s_update_last
```

````
`````

--------------------------------------------------------------------------------

`````{tabs}

````{group-tab} 32

```{doxygenfunction} Hacl_Blake2s_32_blake2s_finish
```

````

````{group-tab} 128

```{doxygenfunction} Hacl_Blake2s_128_blake2s_finish
```

````
`````

### Compatibility

```{doxygenfunction} Hacl_Blake2s_128_store_state128s_to_state32
```

```{doxygenfunction} Hacl_Blake2s_128_load_state128s_from_state32
```

