#include <string.h>

#include "Libcrux_Kem_Kyber_Kyber768.h"
#include "libcrux_kyber.h"

int
Libcrux_Kyber768_GenerateKeyPair(uint8_t* pk,
                                 uint8_t* sk,
                                 const uint8_t* randomness)
{
  libcrux_kyber_kyber768_generate_key_pair_768(randomness)
  memset(pk, 0, KYBER768_PUBLICKEYBYTES);
  memset(sk, 0, KYBER768_SECRETKEYBYTES);
  return 0;
}

int
Libcrux_Kyber768_Encapsulate(uint8_t* ct,
                             uint8_t* ss,
                             const uint8_t* pk,
                             const uint8_t* randomness)
{
  (void)pk;
  (void)randomness;
  memset(ct, 0, KYBER768_CIPHERTEXTBYTES);
  memset(ss, 0, KYBER768_SHAREDSECRETBYTES);
  return 0;
}

int
Libcrux_Kyber768_Decapsulate(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
  (void)sk;
  (void)ct;
  memset(ss, 0, KYBER768_SHAREDSECRETBYTES);
  return 0;
}
