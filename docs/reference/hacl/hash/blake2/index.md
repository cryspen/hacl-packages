# Blake2

BLAKE2 comes in two variants:

* BLAKE2b (or just BLAKE2), and
* BLAKE2s.

BLAKE2b is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes.
It also has a build-in keying mechanism so that it can be used to replace HMAC-based constructions.

BLAKE2s is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes.

```{toctree}
:caption: "Variants:"

blake2b
blake2s
```

