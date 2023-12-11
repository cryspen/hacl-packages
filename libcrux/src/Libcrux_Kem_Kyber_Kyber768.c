#include <string.h>

#include "Libcrux_Kem_Kyber_Kyber768.h"
#include "libcrux_kyber.h"

void
Libcrux_Kyber768_GenerateKeyPair(uint8_t* pk,
                                 uint8_t* sk,
                                 uint8_t randomness[64])
{
  (void)libcrux_kyber_kyber768_generate_key_pair_768(randomness);
  memset(pk, 0, KYBER768_PUBLICKEYBYTES);
  memset(sk, 0, KYBER768_SECRETKEYBYTES);
}

void
Libcrux_Kyber768_Encapsulate(uint8_t* ct,
                             uint8_t* ss,
                             uint8_t (*pk)[1184],
                             uint8_t randomness[32])
{
  (void)libcrux_kyber_kyber768_encapsulate_768(pk, randomness);
  memset(ct, 0, KYBER768_CIPHERTEXTBYTES);
  memset(ss, 0, KYBER768_SHAREDSECRETBYTES);
}

void
Libcrux_Kyber768_Decapsulate(uint8_t ss[32U],
                             uint8_t (*ct)[1088U],
                             uint8_t (*sk)[2400U])
{
  (void)libcrux_kyber_kyber768_decapsulate_768(sk, ct, ss);
  memset(ss, 0, KYBER768_SHAREDSECRETBYTES);
}
