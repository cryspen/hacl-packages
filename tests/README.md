# Test vectors

## blake2b/blake2s

* Both `official.json`s are from the [Reference source code package of BLAKE2].
* The `blake2b.json` is from [emilbayes/blake2b].

## chacha20poly1305

The test vectors are from [Project Wycheproof].

## ed25519

The test vectors are from [Project Wycheproof].

## hmac

The test vectors are from [Project Wycheproof].

## hkdf

The test vectors are from [RFC5869] and [Project Wycheproof].
The BLAKE2{s,b} test vectors were generated with [pyca/cryptography]. 

## p256_ecdh

The test vectors are from [Project Wycheproof].

## p256_ecdsa

The test vectors are from [Project Wycheproof].

## p256k1_ecdsa

The test vectors are from [Project Wycheproof].

## poly1305

The test vectors are from [RFC8439].

## rsapss

The test vectors are from [Project Wycheproof].

*Note:* SHA-1 is not supported in Hacl and thus not tested.

## md5

The test vectors are from [RFC1321].

## sha2

The test vectors are from [Cryptographic Algorithm Validation Program].

## sha3

The test vectors are from [Cryptographic Algorithm Validation Program].

## x25519

The test vectors are from [Project Wycheproof].

## NaCl

The test vectors are generated with [crypto_box] and [sodiumoxide] (see `tools/generate_test_vectors/nacl`).

[Reference source code package of BLAKE2]: https://github.com/BLAKE2/BLAKE2/tree/master/testvectors
[emilbayes/blake2b]: https://github.com/emilbayes/blake2b/blob/master/test-vectors.json
[NIST's Cryptographic Algorithm Validation Program]: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing
[Project Wycheproof]: https://github.com/google/wycheproof/tree/2196000605e45d91097147c9c71f26b72af58003
[RFC1321]: https://datatracker.ietf.org/doc/html/rfc1321
[RFC5869]: https://datatracker.ietf.org/doc/html/rfc5869
[RFC8439]: https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.3
[pyca/cryptography]: https://cryptography.io/en/3.4.2/development/custom-vectors/hkdf.html#creation 
[crypto_box]: https://crates.io/crates/crypto_box
[sodiumoxide]: https://crates.io/crates/sodiumoxide

