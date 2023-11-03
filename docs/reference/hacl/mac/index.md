# MAC

A Message Authentication Code (MAC) provides data integrity and authenticity of a message.

## HMAC

An HMAC is a specific construction of a MAC that involves a cryptographic hash function (see [RFC 2104]).
Thus, an HMAC comes in multiple instantiations.
HACL Packages supports the following ones:

* HMAC-BLAKE2b,
* HMAC-BLAKE2s,
* HMAC-SHA-2-256,
* HMAC-SHA-2-384,
* HMAC-SHA-2-512, and
* HMAC-SHA-1.

Keys must be chosen using a cryptographically strong pseudo-random generator and periodically refreshed.
Note that the key can be of any length up to the specific block length of the used hash algorithm.
This is also mentioned in the API reference below.

### Available Implementations

`````{tabs}
````{group-tab} 32
This implementation works on any CPU.
````

````{group-tab} 128
Support for VEC128 is needed. Please see the [HACL Packages book].
````

````{group-tab} 256
Support for VEC256 is needed. Please see the [HACL Packages book].
````
`````

### API Reference

**Example**


```{literalinclude} ../../../../tests/hmac.cc
:language: C
:dedent:
:start-after: "// ANCHOR(DEFINE)"
:end-before: "// ANCHOR_END(DEFINE)"
```

```{literalinclude} ../../../../tests/hmac.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE)"
:end-before: "// ANCHOR_END(EXAMPLE)"
```

#### BLAKE2b

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_HMAC_compute_blake2b_32
```
````

````{group-tab} 256
```{doxygenfunction} Hacl_HMAC_Blake2b_256_compute_blake2b_256
```
````
`````

#### BLAKE2s

`````{tabs}
````{group-tab} 32
```{doxygenfunction} Hacl_HMAC_compute_blake2s_32
```
````
````{group-tab} 128
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

[hacl packages book]: https://cryspen.com/hacl-packages/algorithms.html
[rfc 2104]: https://www.ietf.org/rfc/rfc2104.txt
