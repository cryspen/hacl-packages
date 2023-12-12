/*
 *    Copyright 2023 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "Libcrux_Kem_Kyber_Kyber768.h"
#include "util.h"

using namespace std;

class KAT
{
public:
  bytes key_generation_seed;
  bytes sha3_256_hash_of_public_key;
  bytes sha3_256_hash_of_secret_key;
  bytes encapsulation_seed;
  bytes sha3_256_hash_of_ciphertext;
  bytes shared_secret;
};

vector<KAT>
read_kats(string path)
{
  ifstream kat_file(path);
  nlohmann::json kats_raw;
  kat_file >> kats_raw;

  vector<KAT> kats;

  // Read test group
  for (auto& kat_raw : kats_raw.items()) {
    auto kat_raw_value = kat_raw.value();

    kats.push_back(KAT{
      .key_generation_seed = from_hex(kat_raw_value["key_generation_seed"]),
      .sha3_256_hash_of_public_key =
        from_hex(kat_raw_value["sha3_256_hash_of_public_key"]),
      .sha3_256_hash_of_secret_key =
        from_hex(kat_raw_value["sha3_256_hash_of_secret_key"]),
      .encapsulation_seed = from_hex(kat_raw_value["encapsulation_seed"]),
      .sha3_256_hash_of_ciphertext =
        from_hex(kat_raw_value["sha3_256_hash_of_ciphertext"]),
      .shared_secret = from_hex(kat_raw_value["shared_secret"]),
    });
  }

  return kats;
}

TEST(Kyber768Test, ConsistencyTest)
{
  uint8_t randomness[64] = { 0 };
  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  std::cerr << "ARE WE HERE? 0.5\n";

  Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);

  std::cerr << "ARE WE HERE? 1\n";

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];
  Libcrux_Kyber768_Encapsulate(
    ciphertext, sharedSecret, &publicKey, randomness);

  std::cerr << "ARE WE HERE? 2\n";

  uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
}

TEST(Kyber768Test, NISTKnownAnswerTest)
{
  auto kats = read_kats("kyber768_nistkats.json");

  uint8_t randomness[64] = { 0 };

  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  for (auto kat : kats) {
    Libcrux_Kyber768_GenerateKeyPair(
      publicKey, secretKey, kat.key_generation_seed.data());

    uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
    uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Encapsulate(
      ciphertext, sharedSecret, &publicKey, randomness);

    uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

    EXPECT_EQ(0,
              memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
    EXPECT_EQ(0,
              memcmp(sharedSecret, kat.shared_secret.data(), KYBER768_SHAREDSECRETBYTES));
  }
}
