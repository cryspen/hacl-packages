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
#include "libcrux_ml_kem.h"
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

void
modify_ciphertext(uint8_t* ciphertext, size_t ciphertext_size)
{
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

void
modify_secret_key(uint8_t* secret_key,
                  size_t secret_key_size,
                  bool modify_implicit_rejection_value)
{
  uint8_t randomness[3];
  generate_random(randomness, 3);

  uint8_t random_byte = randomness[0];
  if (random_byte == 0) {
    random_byte += 1;
  }

  uint16_t random_u16 = (randomness[2] << 8) | randomness[1];

  uint16_t random_position = 0;

  if (modify_implicit_rejection_value == true) {
    random_position = (secret_key_size - 32) + (random_u16 % 32);
  } else {
    random_position = random_u16 % (secret_key_size - 32);
  }

  secret_key[random_position] ^= random_byte;
}

uint8_t*
compute_implicit_rejection_shared_secret(uint8_t* ciphertext,
                                         size_t ciphertext_size,
                                         uint8_t* secret_key,
                                         size_t secret_key_size)
{
  uint8_t* hashInput = new uint8_t[32 + ciphertext_size];
  uint8_t* sharedSecret = new uint8_t[32];

  std::copy(secret_key + (secret_key_size - 32),
            secret_key + secret_key_size,
            hashInput);
  std::copy(ciphertext, ciphertext + ciphertext_size, hashInput + 32);

  Hacl_Hash_SHA3_shake256_hacl(
    32 + ciphertext_size, hashInput, 32, sharedSecret);

  delete[] hashInput;
  return sharedSecret;
}

TEST(Kyber768Test, ConsistencyTest)
{
  uint8_t randomness[64];

  generate_random(randomness, 64);
  auto key_pair = libcrux_ml_kem_mlkem768_generate_key_pair(randomness);
  printf("pk: ");
  print_hex_ln(1184, key_pair.pk);
  printf("sk: ");
  print_hex_ln(2400, key_pair.sk);

  generate_random(randomness, 32);
  auto ctxt = libcrux_ml_kem_mlkem768_encapsulate((uint8_t(*)[1184])key_pair.pk,
                                                  randomness);
  printf("ctxt: ");
  print_hex_ln(1088U, ctxt.fst);
  printf("secret: ");
  print_hex_ln(32, ctxt.snd);

  uint8_t sharedSecret2[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];
  libcrux_ml_kem_mlkem768_decapsulate(
    (uint8_t(*)[2400])key_pair.sk, &ctxt.fst, sharedSecret2);
  printf("secret2: ");
  print_hex_ln(32, sharedSecret2);

  EXPECT_EQ(0,
            memcmp(ctxt.snd,
                   sharedSecret2,
                   LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE));
}

TEST(Kyber768Test, ModifiedCiphertextTest)
{
  uint8_t randomness[64];
  uint8_t publicKey[LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_KEY_SIZE_768];
  uint8_t secretKey[LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768];

  generate_random(randomness, 64);
  auto key_pair = libcrux_ml_kem_mlkem768_generate_key_pair(randomness);

  uint8_t ciphertext[LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE_768];
  uint8_t sharedSecret[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];

  generate_random(randomness, 32);
  auto ctxt = libcrux_ml_kem_mlkem768_encapsulate((uint8_t(*)[1184])key_pair.pk,
                                                  randomness);

  uint8_t sharedSecret2[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];
  modify_ciphertext(ciphertext,
                    LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE_768);
  libcrux_ml_kem_mlkem768_decapsulate(
    (uint8_t(*)[2400])key_pair.sk, &ciphertext, sharedSecret2);

  EXPECT_NE(0,
            memcmp(sharedSecret,
                   sharedSecret2,
                   LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE));

  uint8_t* implicitRejectionSharedSecret =
    compute_implicit_rejection_shared_secret(
      ciphertext,
      LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE_768,
      secretKey,
      LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768);

  EXPECT_EQ(0,
            memcmp(implicitRejectionSharedSecret,
                   sharedSecret2,
                   LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE));
  delete[] implicitRejectionSharedSecret;
}

TEST(Kyber768Test, ModifiedSecretKeyTest)
{
  uint8_t randomness[64];
  uint8_t publicKey[LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_KEY_SIZE_768];
  uint8_t secretKey[LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768];

  generate_random(randomness, 64);
  auto key_pair = libcrux_ml_kem_mlkem768_generate_key_pair(randomness);

  uint8_t ciphertext[LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE_768];
  uint8_t sharedSecret[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];

  generate_random(randomness, 32);
  auto ctxt = libcrux_ml_kem_mlkem768_encapsulate((uint8_t(*)[1184])key_pair.pk,
                                                  randomness);

  uint8_t sharedSecret2[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];
  modify_secret_key(
    secretKey, LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768, false);
  libcrux_ml_kem_mlkem768_decapsulate(
    (uint8_t(*)[2400])key_pair.sk, &ciphertext, sharedSecret2);

  EXPECT_NE(0,
            memcmp(sharedSecret,
                   sharedSecret2,
                   LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE));

  modify_secret_key(
    secretKey, LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768, true);
  libcrux_ml_kem_mlkem768_decapsulate(
    (uint8_t(*)[2400])key_pair.sk, &ciphertext, sharedSecret2);

  uint8_t* implicitRejectionSharedSecret =
    compute_implicit_rejection_shared_secret(
      ciphertext,
      LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE_768,
      secretKey,
      LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768);
  EXPECT_EQ(0,
            memcmp(implicitRejectionSharedSecret,
                   sharedSecret2,
                   LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE));
  delete[] implicitRejectionSharedSecret;
}

TEST(Kyber768Test, NISTKnownAnswerTest)
{
  auto kats = read_kats("kyber768_nistkats.json");

  uint8_t publicKey[LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_KEY_SIZE_768];
  uint8_t secretKey[LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768];

  for (auto kat : kats) {
    // libcrux_ml_kem_mlkem768_generate_key_pair(
    //   publicKey, secretKey, kat.key_generation_seed.data());
    auto key_pair =
      libcrux_ml_kem_mlkem768_generate_key_pair(kat.key_generation_seed.data());
    uint8_t pk_hash[32];
    Hacl_Hash_SHA3_sha3_256(
      pk_hash, publicKey, LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_KEY_SIZE_768);
    EXPECT_EQ(0, memcmp(pk_hash, kat.sha3_256_hash_of_public_key.data(), 32));
    uint8_t sk_hash[32];
    Hacl_Hash_SHA3_sha3_256(
      sk_hash, secretKey, LIBCRUX_ML_KEM_MLKEM768_SECRET_KEY_SIZE_768);
    EXPECT_EQ(0, memcmp(sk_hash, kat.sha3_256_hash_of_secret_key.data(), 32));

    uint8_t ciphertext[LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE_768];
    uint8_t sharedSecret[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];
    // libcrux_ml_kem_mlkem768_encapsulate(
    //   ciphertext, sharedSecret, &publicKey, kat.encapsulation_seed.data());
    auto ctxt = libcrux_ml_kem_mlkem768_encapsulate(
      (uint8_t(*)[1184])key_pair.pk, kat.encapsulation_seed.data());
    uint8_t ct_hash[32];
    Hacl_Hash_SHA3_sha3_256(
      ct_hash, ciphertext, LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_SIZE_768);
    EXPECT_EQ(0, memcmp(ct_hash, kat.sha3_256_hash_of_ciphertext.data(), 32));
    EXPECT_EQ(0,
              memcmp(sharedSecret,
                     kat.shared_secret.data(),
                     LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE));

    uint8_t sharedSecret2[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];
    // libcrux_ml_kem_mlkem768_decapsulate(sharedSecret2, &ciphertext,
    // &secretKey);
    libcrux_ml_kem_mlkem768_decapsulate(
      (uint8_t(*)[2400])key_pair.sk, &ciphertext, sharedSecret2);

    EXPECT_EQ(0,
              memcmp(sharedSecret,
                     sharedSecret2,
                     LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE));
  }
}
