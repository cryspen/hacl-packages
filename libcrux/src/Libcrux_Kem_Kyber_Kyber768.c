#include <string.h>

#include "Libcrux_Kem_Kyber_Kyber768.h"
#include "libcrux_kyber.h"

void
Libcrux_Kyber768_GenerateKeyPair(uint8_t* pk,
                                 uint8_t* sk,
                                 uint8_t randomness[64])
{
  libcrux_kyber_types_MlKemKeyPair___2400size_t_1184size_t result =
    libcrux_kyber_kyber768_generate_key_pair(randomness);

  memcpy(pk, result.pk, KYBER768_PUBLICKEYBYTES);
  memcpy(sk, result.sk, KYBER768_SECRETKEYBYTES);
}

void
Libcrux_Kyber768_Encapsulate(uint8_t* ct,
                             uint8_t* ss,
                             uint8_t (*pk)[1184],
                             uint8_t randomness[32])
{
  K___libcrux_kyber_types_MlKemCiphertext__1088size_t___uint8_t_32size_t_
    result = libcrux_kyber_kyber768_encapsulate(pk, randomness);
  memcpy(ct, result.fst, KYBER768_CIPHERTEXTBYTES);
  memcpy(ss, result.snd, KYBER768_SHAREDSECRETBYTES);
}

void
Libcrux_Kyber768_Decapsulate(uint8_t ss[32U],
                             uint8_t (*ct)[1088U],
                             uint8_t (*sk)[2400U])
{
  libcrux_kyber_kyber768_decapsulate(sk, ct, ss);
}
