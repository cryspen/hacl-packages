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

#include "Hacl_Hash_SHA3.h"
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

void modify_ciphertext(uint8_t* ciphertext, size_t ciphertext_size) {
    uint8_t randomness[3];
    generate_random(randomness, 3);

    uint8_t random_byte = randomness[0];
    if (random_byte == 0) {
        random_byte += 1;
    }

    uint16_t random_u16 = (randomness[2] << 8) | randomness[1];

    uint16_t random_position = random_u16 % ciphertext_size;

    ciphertext[random_position] ^= random_byte;
}

void modify_secret_key(uint8_t* secret_key, size_t secret_key_size, bool modify_implicit_rejection_value) {
    uint8_t randomness[3];
    generate_random(randomness, 3);

    uint8_t random_byte = randomness[0];
    if (random_byte == 0) {
        random_byte += 1;
    }

    uint16_t random_u16 = (randomness[2] << 8) | randomness[1];

    uint16_t random_position = 0;

    if(modify_implicit_rejection_value == true) {
        random_position = (secret_key_size - 32) + (random_u16 % 32);
    } else {
        random_position = random_u16 % (secret_key_size - 32);
    }

    secret_key[random_position] ^= random_byte;
}

uint8_t* compute_implicit_rejection_shared_secret(uint8_t* ciphertext, size_t ciphertext_size, uint8_t* secret_key, size_t secret_key_size) {
    uint8_t* hashInput = new uint8_t[32 + ciphertext_size];
    uint8_t* sharedSecret = new uint8_t[32];

    std::copy(secret_key + (secret_key_size - 32), secret_key + secret_key_size, hashInput);
    std::copy(ciphertext, ciphertext + ciphertext_size, hashInput + 32);

    Hacl_Hash_SHA3_shake256_hacl(32 + ciphertext_size, hashInput, 32, sharedSecret);

    delete [] hashInput;
    return sharedSecret;
}

TEST(Kyber768Test, ConsistencyTest)
{
  uint8_t randomness[64];
  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  generate_random(randomness, 64);
  Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];

  generate_random(randomness, 32);
  Libcrux_Kyber768_Encapsulate(
    ciphertext, sharedSecret, &publicKey, randomness);

  uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
}

TEST(Kyber768Test, ModifiedCiphertextTest)
{
  uint8_t randomness[64];
  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  generate_random(randomness, 64);
  Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];

  generate_random(randomness, 32);
  Libcrux_Kyber768_Encapsulate(
    ciphertext, sharedSecret, &publicKey, randomness);

  uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  modify_ciphertext(ciphertext, KYBER768_CIPHERTEXTBYTES);
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_NE(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));

  uint8_t* implicitRejectionSharedSecret = compute_implicit_rejection_shared_secret(ciphertext, KYBER768_CIPHERTEXTBYTES, secretKey, KYBER768_SECRETKEYBYTES);

  EXPECT_EQ(0, memcmp(implicitRejectionSharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
  delete [] implicitRejectionSharedSecret;
}

TEST(Kyber768Test, ModifiedSecretKeyTest)
{
  uint8_t randomness[64];
  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  generate_random(randomness, 64);
  Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];

  generate_random(randomness, 32);
  Libcrux_Kyber768_Encapsulate(
    ciphertext, sharedSecret, &publicKey, randomness);

  uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  modify_secret_key(secretKey, KYBER768_SECRETKEYBYTES, false);
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_NE(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));

  modify_secret_key(secretKey, KYBER768_SECRETKEYBYTES, true);
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  uint8_t* implicitRejectionSharedSecret = compute_implicit_rejection_shared_secret(ciphertext, KYBER768_CIPHERTEXTBYTES, secretKey, KYBER768_SECRETKEYBYTES);
  EXPECT_EQ(0, memcmp(implicitRejectionSharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
  delete [] implicitRejectionSharedSecret;
}

TEST(Kyber768Test, NISTKnownAnswerTest)
{
  auto kats = read_kats("kyber768_nistkats.json");

  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  for (auto kat : kats) {
    Libcrux_Kyber768_GenerateKeyPair(
      publicKey, secretKey, kat.key_generation_seed.data());
    uint8_t pk_hash[32];
    Hacl_Hash_SHA3_sha3_256(pk_hash, publicKey, KYBER768_PUBLICKEYBYTES);
    EXPECT_EQ(0,
              memcmp(pk_hash, kat.sha3_256_hash_of_public_key.data(), 32));
    uint8_t sk_hash[32];
    Hacl_Hash_SHA3_sha3_256(sk_hash, secretKey, KYBER768_SECRETKEYBYTES);
    EXPECT_EQ(0,
              memcmp(sk_hash, kat.sha3_256_hash_of_secret_key.data(), 32));

    uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
    uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Encapsulate(
      ciphertext, sharedSecret, &publicKey, kat.encapsulation_seed.data());
    uint8_t ct_hash[32];
    Hacl_Hash_SHA3_sha3_256(ct_hash, ciphertext, KYBER768_CIPHERTEXTBYTES);
    EXPECT_EQ(0,
              memcmp(ct_hash, kat.sha3_256_hash_of_ciphertext.data(), 32));
    EXPECT_EQ(0,
              memcmp(sharedSecret,
                     kat.shared_secret.data(),
                     KYBER768_SHAREDSECRETBYTES));

    uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

    EXPECT_EQ(0,
              memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
  }
}
