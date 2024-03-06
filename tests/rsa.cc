/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>

#include <gtest/gtest.h>

#include "Hacl_RSA.h"
#include "Hacl_Spec.h"
#include "util.h"

TEST(ApiSuite, ApiTest)
{
  // ANCHOR(EXAMPLE)
  // We want to enc and dec a message.

  // Keys
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  // Note: This is not in HACL*.
  //       You need to bring your own keys.
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSA_new_rsa_load_skey(modBits, eBits, dBits, mod, e, d);

  if (skey == NULL) {
    //Error
  }

  uint64_t* pkey = Hacl_RSA_new_rsa_load_pkey(modBits, eBits, mod, e);

  if (pkey == NULL) {
    //Error
  }

  // Message
  uint8_t msg[256] = {0};
  for (int i = 0; i < 256; i++) msg[i] = i;

  // Ciphertext
  uint8_t cipher[256] {0}; 

  // Encrypt
  bool res_enc = Hacl_RSA_rsa_enc(modBits,
                                  eBits,
                                  pkey,
                                  msg,
                                  cipher);

  if (!res_enc) {
    // Error
    cout << "Raw RSA Encryption failed!\n";
  }

  uint8_t msg2[256] = {0};
  bool res_dec = Hacl_RSA_rsa_dec(modBits,
                                  eBits,
                                  dBits,
                                  skey,
                                  cipher,
                                  msg2);

  if (!res_dec) {
    // Error
    cout << "Raw RSA Decryption failed!\n";
  }

  EXPECT_EQ(strncmp((char*)msg,
                    (char*)msg2,
                    256),
            0);

  free(pkey);
  free(skey);
  free(mod);
  free(d);
  free(e);
  // ANCHOR_END(EXAMPLE)

  EXPECT_TRUE(res_enc);
  EXPECT_TRUE(res_dec);
}


void
sign(bytes e,
     bytes d,
     bytes n,
     bytes salt,
     Spec_Hash_Definitions_hash_alg alg,
     bytes msg,
     bytes& sgnt,
     bool* out);

void
verify(bytes e,
       bytes n,
       uint32_t saltLen,
       Spec_Hash_Definitions_hash_alg alg,
       bytes msg,
       bytes sgnt,
       bool* out);


TEST(BadSecretKey, RsaPssLoadKey)
{
  // (e, d, n)
  std::vector<std::tuple<bytes, bytes, bytes>> tests{
    { from_hex(""), from_hex(""), from_hex("") },
    { from_hex(""), from_hex("AA"), from_hex("") },
    { from_hex("AA"), from_hex(""), from_hex("") },
    { from_hex("AA"), from_hex("AA"), from_hex("") },
    { from_hex("AA"), from_hex("AA"), from_hex("AA") },
    { from_hex("AA"), from_hex("AAAA"), from_hex("AA") },
    { from_hex("AAAA"), from_hex("AA"), from_hex("AA") },
    { from_hex("AAAA"), from_hex("AAAA"), from_hex("AA") },
  };

  for (auto test : tests) {
    bytes e, d, n;
    std::tie(e, d, n) = test;

    uint64_t* skey = Hacl_RSA_new_rsa_load_skey(
      n.size() * 8, e.size() * 8, d.size() * 8, n.data(), e.data(), d.data());

    ASSERT_TRUE(skey == NULL);
  }
}

TEST(BadPublicKey, RsaPssLoadKey)
{
  // (e, n)
  std::vector<std::tuple<bytes, bytes>> tests{
    { from_hex(""), from_hex("") },
    { from_hex(""), from_hex("FF") },
    { from_hex("AA"), from_hex("") },
  };

  for (auto test : tests) {
    bytes e, n;
    std::tie(e, n) = test;

    uint64_t* pkey = Hacl_RSA_new_rsa_load_pkey(
      n.size() * 8, e.size() * 8, n.data(), e.data());

    ASSERT_TRUE(pkey == NULL);
  }
}
