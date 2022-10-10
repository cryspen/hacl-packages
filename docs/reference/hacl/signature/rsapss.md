# RSAPSS

RSASSA-PSS as defined in [RFC 8017].

<!--
## Example

TODO(Example):

```{literalinclude} ../../../../tests/rsapss.cc
:language: C
:dedent:
:start-after: "// START"
:end-before: "// END"
```
-->

## API Reference

```C
#include "Hacl_RSAPSS.h"
```

```{doxygenfunction} Hacl_RSAPSS_new_rsapss_load_skey
```

Load a secret key from key parts.

* `modBits` Count of bits in modulus (`n`).
* `eBits` Count of bits in `e` value.
* `dBits` Count of bits in `d` value.
* `nb` Pointer to `ceil(modBits / 8)` bytes where the modulus (`n`) is read from.
* `eb` Pointer to `ceil(modBits / 8)` bytes where the `e` value is read from.
* `db` Pointer to `ceil(modBits / 8)` bytes where the `d` value is read from.

Returns an allocated secret key. Note: caller must take care to `free()` the created key.

```{doxygenfunction} Hacl_RSAPSS_new_rsapss_load_pkey
```

Load a public key from key parts.

* `modBits` Count of bits in modulus (`n`).
* `eBits` Count of bits in `e` value.
* `nb` Pointer to `ceil(modBits / 8)` bytes where the modulus (`n`) is read from.
* `eb` Pointer to `ceil(modBits / 8)` bytes where the `e` value is read from.

Returns an allocated public key. Note: caller must take care to `free()` the created key.

```{doxygenfunction} Hacl_RSAPSS_rsapss_sign
```

Sign a message `msg` and write the signature to `sgnt`.

* `a` Hash algorithm to use. Allowed values for `a` are ...
  * Spec_Hash_Definitions_SHA2_256,
  * Spec_Hash_Definitions_SHA2_384, and
  * Spec_Hash_Definitions_SHA2_512.
* `modBits` Count of bits in the modulus (`n`).
* `eBits` Count of bits in `e` value.
* `dBits` Count of bits in `d` value.
* `skey` Pointer to secret key created by `Hacl_RSAPSS_new_rsapss_load_skey`.
* `saltLen` Length of salt.
* `salt` Pointer to `saltLen` bytes where the salt is read from.
* `msgLen` Length of message.
* `msg` Pointer to `msgLen` bytes where the message is read from.
* `sgnt` Pointer to `ceil(modBits / 8)` bytes where the signature is written to.

Returns true if and only if signing was successful.

```{doxygenfunction} Hacl_RSAPSS_rsapss_verify
```

Verify the signature `sgnt` of a message `msg`.

* `a` Hash algorithm to use.
* `modBits` Count of bits in the modulus (`n`).
* `eBits` Count of bits in `e` value.
* `pkey` Pointer to public key created by `Hacl_RSAPSS_new_rsapss_load_pkey`.
* `saltLen` Length of salt.
* `sgntLen` Length of signature.
* `sgnt` Pointer to `sgntLen` bytes where the signature is read from.
* `msgLen` Length of message.
* `msg` Pointer to `msgLen` bytes where the message is read from.

Returns true if and only if the signature is valid.

--------------------------------------------------------------------------------

```{doxygenfunction} Hacl_RSAPSS_rsapss_skey_sign
```

Sign a message `msg` and write the signature to `sgnt`.

* `a` Hash algorithm to use.
* `modBits` Count of bits in the modulus (`n`).
* `eBits` Count of bits in `e` value.
* `dBits` Count of bits in `d` value.
* `nb` Pointer to `ceil(modBits / 8)` bytes where the modulus (`n`) is read from.
* `eb` Pointer to `ceil(modBits / 8)` bytes where the `e` value is read from.
* `db` Pointer to `ceil(modBits / 8)` bytes where the `d` value is read from.
* `saltLen` Length of salt.
* `salt` Pointer to `saltLen` bytes where the salt is read from.
* `msgLen` Length of message.
* `msg` Pointer to `msgLen` bytes where the message is read from.
* `sgnt` Pointer to `ceil(modBits / 8)` bytes where the signature is written to.

Returns true if and only if signing was successful.

```{doxygenfunction} Hacl_RSAPSS_rsapss_pkey_verify
```

Verify the signature `sgnt` of a message `msg`.

* `a` Hash algorithm to use.
* `modBits` Count of bits in the modulus (`n`).
* `eBits` Count of bits in `e` value.
* `nb` Pointer to `ceil(modBits / 8)` bytes where the modulus (`n`) is read from.
* `eb` Pointer to `ceil(modBits / 8)` bytes where the `e` value is read from.
* `saltLen` Length of salt.
* `sgntLen` Length of signature.
* `sgnt` Pointer to `sgntLen` bytes where the signature is read from.
* `msgLen` Length of message.
* `msg` Pointer to `msgLen` bytes where the message is read from.

Returns true if and only if the signature is valid.

[rfc 8017]: https://www.rfc-editor.org/rfc/rfc8017
