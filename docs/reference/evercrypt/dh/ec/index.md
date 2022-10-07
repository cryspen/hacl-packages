# Elliptic-Curve

Elliptic-curve Diffie-Hellman key agreement on Curve25519.

## API Reference

```C
#include "EverCrypt_Curve25519.h"
```

```{doxygenfunction} EverCrypt_Curve25519_scalarmult
```

Compute the scalar multiple of a point.

`shared` Pointer to 32 bytes of memory, allocated by the caller, where the resulting point is written to.
`my_priv` Pointer to 32 bytes of memory, allocated by the caller, where the secret/private key is read from.
`their_pub` Pointer to 32 bytes of memory, allocated by the caller, where the public point is read from.

```{doxygenfunction} EverCrypt_Curve25519_secret_to_public
```

Calculate a public point from a secret/private key.

This computes a scalar multiplication of the secret/private key with the curve's basepoint.

`pub` Pointer to 32 bytes of memory, allocated by the caller, where the resulting point is written to.
`priv` Pointer to 32 bytes of memory, allocated by the caller, where the secret/private key is read from.

```{doxygenfunction} EverCrypt_Curve25519_ecdh
```

Execute the diffie-hellmann key exchange.

`shared` Pointer to 32 bytes of memory, allocated by the caller, where the resulting point is written to.
`my_priv` Pointer to 32 bytes of memory, allocated by the caller, where **our** secret/private key is read from.
`their_pub` Pointer to 32 bytes of memory, allocated by the caller, where **their** public point is read from.

