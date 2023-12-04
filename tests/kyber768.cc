/*
 *    Copyright 2023 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>
#include <gtest/gtest.h>

#include "Libcrux_Kem_Kyber_Kyber768.h"

using namespace std;

TEST(Kyber768Test, ConsistencyTest)
{
  uint8_t randomness[64] = {0};
  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  int rv = Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);
  EXPECT_EQ(0, rv);

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];
  rv = Libcrux_Kyber768_Encapsulate(ciphertext, sharedSecret, publicKey, randomness);

  EXPECT_EQ(0, rv);

  uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  rv = Libcrux_Kyber768_Decapsulate(sharedSecret2, ciphertext, secretKey);
  EXPECT_EQ(0, rv);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
}
