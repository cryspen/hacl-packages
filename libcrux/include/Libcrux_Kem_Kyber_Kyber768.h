#ifndef __Libcrux_Kem_Kyber_Kyber768_H
#define __Libcrux_Kem_Kyber_Kyber768_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include <inttypes.h>

#define KYBER768_SECRETKEYBYTES 2400
#define KYBER768_PUBLICKEYBYTES 1184
#define KYBER768_CIPHERTEXTBYTES 1088
#define KYBER768_SHAREDSECRETBYTES 32
  void Libcrux_Kyber768_GenerateKeyPair(uint8_t* pk,
                                        uint8_t* sk,
                                        uint8_t randomness[64]);

  void Libcrux_Kyber768_Encapsulate(uint8_t* ct,
                                    uint8_t* ss,
                                    uint8_t (*pk)[1184],
                                    uint8_t randomness[32]);

  void Libcrux_Kyber768_Decapsulate(uint8_t ss[32U],
                                    uint8_t (*ct)[1088U],
                                    uint8_t (*sk)[2400U]);

#if defined(__cplusplus)
}
#endif

#define __Libcrux_Kem_Kyber_Kyber768_H_DEFINED
#endif
