# Elliptic-Curve

Diffie-Hellman key exchange on Curve25519.

## API Reference

```C
#include "EverCrypt_Curve25519.h"
```

```{doxygenfunction} EverCrypt_Curve25519_scalarmult
```

Compute the scalar multiple of a point.

`shared` Pointer to 32 bytes of memory, allocated by the caller, where the resulting point is written to.
`my_priv` Pointer to secret/private key.
`their_pub` Pointer to public point.

```{doxygenfunction} EverCrypt_Curve25519_secret_to_public
```

Calculate a public point from a secret/private key.

This computes a scalar multiplication of the secret/private key with the curve's basepoint.

`pub` Pointer to 32 bytes of memory, allocated by the caller, where the resulting point is written to.
`priv` Pointer to secret/private key.

```{doxygenfunction} EverCrypt_Curve25519_ecdh
```

Execute the diffie-hellmann key exchange.

`shared` Pointer to 32 bytes of memory, allocated by the caller, where the resulting point is written to.
`my_priv` Pointer to **our** secret/private key.
`their_pub` Pointer to **their** public point.

