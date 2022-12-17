/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "Hacl_NaCl.h"
#include "util.h"

// ANCHOR(example define box)
// Note: HACL Packages will provide this (or a similar) define in a later
// version.
#define HACL_NACL_CRYPTO_BOX_SECRETKEYBYTES 32
#define HACL_NACL_CRYPTO_BOX_PUBLICKEYBYTES 32
#define HACL_NACL_CRYPTO_BOX_BEFORENMBYTES 32
#define HACL_NACL_CRYPTO_BOX_NONCEBYTES 24
#define HACL_NACL_CRYPTO_BOX_MACBYTES 16
// ANCHOR_END(example define box)

// ANCHOR(example define secretbox)
// Note: HACL Packages will provide this (or a similar) define in a later
// version.
#define HACL_NACL_CRYPTO_SECRETBOX_KEYBYTES 32
#define HACL_NACL_CRYPTO_SECRETBOX_NONCEBYTES 24
#define HACL_NACL_CRYPTO_SECRETBOX_MACBYTES 16
// ANCHOR_END(example define secretbox)

using json = nlohmann::json;
using namespace std;

// ----- NaCl Box --------------------------------------------------------------

TEST(ApiSuite, ApiTest)
{
  // Documentation.
  // Lines after ANCHOR and before ANCHOR_END are used in documentation.

  // ANCHOR(EXAMPLE SETUP)
  // Alice wants to encrypt a message to Bob.
  // Thus, both parties do need cryptographic keys.
  //
  // Note: HACL* does not provide randomness yet.
  //       Thus, you must bring your own random (including keys and nonces).

  // Alice
  unsigned char alice_pk[HACL_NACL_CRYPTO_BOX_PUBLICKEYBYTES];
  unsigned char alice_sk[HACL_NACL_CRYPTO_BOX_SECRETKEYBYTES];

  // Example: The `crypto_box_keypair_` function does not exist in HACL*.
  crypto_box_keypair_alice(alice_sk, alice_pk);

  // Bob
  unsigned char bob_pk[HACL_NACL_CRYPTO_BOX_PUBLICKEYBYTES];
  unsigned char bob_sk[HACL_NACL_CRYPTO_BOX_SECRETKEYBYTES];

  // Example: The `crypto_box_keypair_` function does not exist in HACL*.
  crypto_box_keypair_bob(bob_sk, bob_pk);
  // ANCHOR_END(EXAMPLE SETUP)

  {
    // ANCHOR(EXAMPLE ONESHOT COMBINED)
    const char* plaintext = "Hello, World!";
    const size_t plaintext_size = strlen(plaintext);

    // Generate a nonce.
    uint8_t nonce[HACL_NACL_CRYPTO_BOX_NONCEBYTES];
    generate_random(nonce, HACL_NACL_CRYPTO_BOX_NONCEBYTES);

    // Alice encrypts a message to Bob.
    uint8_t* ciphertext =
      (uint8_t*)malloc(HACL_NACL_CRYPTO_BOX_MACBYTES + plaintext_size);
    uint32_t res_enc = Hacl_NaCl_crypto_box_easy(
      ciphertext, (uint8_t*)plaintext, plaintext_size, nonce, bob_pk, alice_sk);

    if (res_enc != 0) {
      // Encryption error
    }

    // Bob decrypts a message from Alice.
    uint8_t* decrypted = (uint8_t*)malloc(plaintext_size);
    uint32_t res_dec = Hacl_NaCl_crypto_box_open_easy(
      decrypted,
      ciphertext,
      HACL_NACL_CRYPTO_BOX_MACBYTES + plaintext_size,
      nonce,
      alice_pk,
      bob_sk);

    if (res_dec != 0) {
      // Decryption error
    }

    free(decrypted);
    free(ciphertext);
    // ANCHOR_END(EXAMPLE ONESHOT COMBINED)

    ASSERT_EQ(res_enc, 0);
    ASSERT_EQ(res_dec, 0);
  }

  {
    // ANCHOR(EXAMPLE ONESHOT DETACHED)
    const char* plaintext = "Hello, World!";
    const size_t plaintext_size = strlen(plaintext);

    // Generate a nonce.
    uint8_t nonce[HACL_NACL_CRYPTO_BOX_NONCEBYTES];
    generate_random(nonce, HACL_NACL_CRYPTO_BOX_NONCEBYTES);

    // Alice encrypts a message to Bob.
    uint8_t tag[HACL_NACL_CRYPTO_BOX_MACBYTES];
    uint8_t* ciphertext = (uint8_t*)malloc(plaintext_size);
    uint32_t res_enc = Hacl_NaCl_crypto_box_detached(ciphertext,
                                                     tag,
                                                     (uint8_t*)plaintext,
                                                     plaintext_size,
                                                     nonce,
                                                     bob_pk,
                                                     alice_sk);

    if (res_enc != 0) {
      // Encryption error
    }

    // Bob decrypts a message from Alice.
    uint8_t* decrypted = (uint8_t*)malloc(plaintext_size);
    uint32_t res_dec = Hacl_NaCl_crypto_box_open_detached(
      decrypted, ciphertext, tag, plaintext_size, nonce, alice_pk, bob_sk);

    if (res_dec != 0) {
      // Decryption error
    }

    free(decrypted);
    free(ciphertext);
    // ANCHOR_END(EXAMPLE ONESHOT DETACHED)

    ASSERT_EQ(res_enc, 0);
    ASSERT_EQ(res_dec, 0);
  }

  {
    // ANCHOR(EXAMPLE PRECOMPUTED COMBINED)
    uint8_t k[HACL_NACL_CRYPTO_BOX_BEFORENMBYTES];
    // Precompute key `k`.
    uint32_t res = Hacl_NaCl_crypto_box_beforenm(k, bob_pk, alice_sk);

    const char* plaintext = "Hello, World!";
    const size_t plaintext_size = strlen(plaintext);

    // Generate a nonce.
    uint8_t nonce[HACL_NACL_CRYPTO_BOX_NONCEBYTES];
    generate_random(nonce, HACL_NACL_CRYPTO_BOX_NONCEBYTES);

    // Alice encrypts a message to Bob.
    uint8_t* ciphertext =
      (uint8_t*)malloc(HACL_NACL_CRYPTO_BOX_MACBYTES + plaintext_size);
    uint32_t res_enc = Hacl_NaCl_crypto_box_easy_afternm(
      ciphertext, (uint8_t*)plaintext, plaintext_size, nonce, k);

    if (res_enc != 0) {
      // Encryption error
    }

    // Bob decrypts a message from Alice.
    uint8_t* decrypted = (uint8_t*)malloc(plaintext_size);
    uint32_t res_dec = Hacl_NaCl_crypto_box_open_easy_afternm(
      decrypted,
      ciphertext,
      HACL_NACL_CRYPTO_BOX_MACBYTES + plaintext_size,
      nonce,
      k);

    if (res_dec != 0) {
      // Decryption error
    }

    free(decrypted);
    free(ciphertext);
    // ANCHOR_END(EXAMPLE PRECOMPUTED COMBINED)

    ASSERT_EQ(res_enc, 0);
    ASSERT_EQ(res_dec, 0);
  }

  {
    // ANCHOR(EXAMPLE PRECOMPUTED DETACHED)
    uint8_t k[HACL_NACL_CRYPTO_BOX_BEFORENMBYTES];
    // Precompute key `k`.
    uint32_t res = Hacl_NaCl_crypto_box_beforenm(k, bob_pk, alice_sk);

    const char* plaintext = "Hello, World!";
    const size_t plaintext_size = strlen(plaintext);

    // Generate a nonce.
    uint8_t nonce[HACL_NACL_CRYPTO_BOX_NONCEBYTES];
    generate_random(nonce, HACL_NACL_CRYPTO_BOX_NONCEBYTES);

    // Alice encrypts a message to Bob.
    uint8_t tag[HACL_NACL_CRYPTO_BOX_MACBYTES];
    uint8_t* ciphertext = (uint8_t*)malloc(plaintext_size);
    uint32_t res_enc = Hacl_NaCl_crypto_box_detached_afternm(
      ciphertext, tag, (uint8_t*)plaintext, plaintext_size, nonce, k);

    if (res_enc != 0) {
      // Encryption error
    }

    // Bob decrypts a message from Alice.
    uint8_t* decrypted = (uint8_t*)malloc(plaintext_size);
    uint32_t res_dec = Hacl_NaCl_crypto_box_open_detached_afternm(
      decrypted, ciphertext, tag, plaintext_size, nonce, k);

    if (res_dec != 0) {
      // Decryption error
    }

    free(decrypted);
    free(ciphertext);
    // ANCHOR_END(EXAMPLE PRECOMPUTED DETACHED)

    ASSERT_EQ(res_enc, 0);
    ASSERT_EQ(res_dec, 0);
  }

  // ---------------------------------------------------------------------------

  // ANCHOR(EXAMPLE SETUP SECRETBOX)
  // Generate a symmetric key for encryption.
  uint8_t key[HACL_NACL_CRYPTO_SECRETBOX_KEYBYTES];
  generate_random(key, HACL_NACL_CRYPTO_SECRETBOX_KEYBYTES);
  // ANCHOR_END(EXAMPLE SETUP SECRETBOX)

  {
    // ANCHOR(EXAMPLE SECRET EASY)
    const char* plaintext = "Hello, World!";
    const size_t plaintext_size = strlen(plaintext);

    // Generate a nonce.
    uint8_t nonce[HACL_NACL_CRYPTO_SECRETBOX_NONCEBYTES];
    generate_random(nonce, HACL_NACL_CRYPTO_SECRETBOX_NONCEBYTES);

    // Encrypt.
    uint8_t* ciphertext =
      (uint8_t*)malloc(HACL_NACL_CRYPTO_SECRETBOX_MACBYTES + plaintext_size);
    uint32_t res_enc = Hacl_NaCl_crypto_secretbox_easy(
      ciphertext, (uint8_t*)plaintext, plaintext_size, nonce, key);

    // Decrypt.
    uint8_t* decrypted = (uint8_t*)malloc(plaintext_size);
    uint32_t res_dec = Hacl_NaCl_crypto_secretbox_open_easy(
      decrypted,
      ciphertext,
      HACL_NACL_CRYPTO_SECRETBOX_MACBYTES + plaintext_size,
      nonce,
      key);

    free(decrypted);
    free(ciphertext);
    // ANCHOR_END(EXAMPLE SECRET EASY)

    ASSERT_EQ(res_enc, 0);
    ASSERT_EQ(res_dec, 0);
  }

  {
    // ANCHOR(EXAMPLE SECRET DETACHED)
    const char* plaintext = "Hello, World!";
    const size_t plaintext_size = strlen(plaintext);

    // Generate a nonce.
    uint8_t nonce[HACL_NACL_CRYPTO_SECRETBOX_NONCEBYTES];
    generate_random(nonce, HACL_NACL_CRYPTO_SECRETBOX_NONCEBYTES);

    // Encrypt.
    uint8_t* ciphertext = (uint8_t*)malloc(plaintext_size);
    uint8_t tag[HACL_NACL_CRYPTO_SECRETBOX_MACBYTES];
    uint32_t res_enc = Hacl_NaCl_crypto_secretbox_detached(
      ciphertext, tag, (uint8_t*)plaintext, plaintext_size, nonce, key);

    // Decrypt.
    uint8_t* decrypted = (uint8_t*)malloc(plaintext_size);
    uint32_t res_dec = Hacl_NaCl_crypto_secretbox_open_detached(
      decrypted, ciphertext, tag, plaintext_size, nonce, key);

    free(decrypted);
    free(ciphertext);
    // ANCHOR_END(EXAMPLE SECRET DETACHED)

    ASSERT_EQ(res_enc, 0);
    ASSERT_EQ(res_dec, 0);
  }
}

typedef struct
{
  bytes alice_sk;
  bytes alice_pk;
  bytes bob_sk;
  bytes bob_pk;
  bytes nonce;
  bytes plaintext;
  bytes ciphertext;
} BoxTestCase;

class NaClBoxSuite : public ::testing::TestWithParam<BoxTestCase>
{};

TEST_P(NaClBoxSuite, EasyKAT)
{
  auto test = GetParam();

  // Encrypt (Alice)
  {
    bytes got_ciphertext(HACL_NACL_CRYPTO_BOX_MACBYTES + test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_easy(got_ciphertext.data(),
                                             test.plaintext.data(),
                                             test.plaintext.size(),
                                             test.nonce.data(),
                                             test.bob_pk.data(),
                                             test.alice_sk.data());
    ASSERT_EQ(res, 0);
    EXPECT_EQ(test.ciphertext, got_ciphertext);
  }

  // Encrypt (Bob) -- Sanity check.
  {
    bytes got_ciphertext(HACL_NACL_CRYPTO_BOX_MACBYTES + test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_easy(got_ciphertext.data(),
                                             test.plaintext.data(),
                                             test.plaintext.size(),
                                             test.nonce.data(),
                                             test.alice_pk.data(),
                                             test.bob_sk.data());
    ASSERT_EQ(res, 0);
    EXPECT_EQ(test.ciphertext, got_ciphertext);
  }

  // Decrypt (Alice)
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_open_easy(got_plaintext.data(),
                                                  test.ciphertext.data(),
                                                  test.ciphertext.size(),
                                                  test.nonce.data(),
                                                  test.bob_pk.data(),
                                                  test.alice_sk.data());
    ASSERT_EQ(res, 0);
    EXPECT_EQ(test.plaintext, got_plaintext);
  }

  // Decrypt (Bob) -- Sanity check.
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_open_easy(got_plaintext.data(),
                                                  test.ciphertext.data(),
                                                  test.ciphertext.size(),
                                                  test.nonce.data(),
                                                  test.alice_pk.data(),
                                                  test.bob_sk.data());
    ASSERT_EQ(res, 0);
    EXPECT_EQ(test.plaintext, got_plaintext);
  }
}

TEST_P(NaClBoxSuite, EasyDetachedKAT)
{
  auto test = GetParam();

  bytes expected_tag =
    bytes(test.ciphertext.begin(),
          test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES);
  bytes expected_ciphertext =
    bytes(test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES,
          test.ciphertext.end());

  // Encrypt
  {
    bytes got_tag(HACL_NACL_CRYPTO_BOX_MACBYTES);
    bytes got_ciphertext(test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_detached(got_ciphertext.data(),
                                                 got_tag.data(),
                                                 test.plaintext.data(),
                                                 test.plaintext.size(),
                                                 test.nonce.data(),
                                                 test.bob_pk.data(),
                                                 test.alice_sk.data());
    ASSERT_EQ(res, 0);
    ASSERT_EQ(expected_tag, got_tag);
    ASSERT_EQ(expected_ciphertext, got_ciphertext);
  }

  // Decrypt
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res =
      Hacl_NaCl_crypto_box_open_detached(got_plaintext.data(),
                                         expected_ciphertext.data(),
                                         expected_tag.data(),
                                         test.plaintext.size(),
                                         test.nonce.data(),
                                         test.bob_pk.data(),
                                         test.alice_sk.data());
    ASSERT_EQ(res, 0);
    EXPECT_EQ(test.plaintext, got_plaintext);
  }
}

TEST_P(NaClBoxSuite, SplitKAT)
{
  auto test = GetParam();

  bytes k(HACL_NACL_CRYPTO_BOX_BEFORENMBYTES);
  uint32_t res = Hacl_NaCl_crypto_box_beforenm(
    k.data(), test.bob_pk.data(), test.alice_sk.data());
  EXPECT_EQ(res, 0);

  // Encrypt
  {
    bytes got_ciphertext(HACL_NACL_CRYPTO_BOX_MACBYTES + test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_easy_afternm(got_ciphertext.data(),
                                                     test.plaintext.data(),
                                                     test.plaintext.size(),
                                                     test.nonce.data(),
                                                     k.data());
    ASSERT_EQ(res, 0);
    EXPECT_EQ(test.ciphertext, got_ciphertext);
  }

  // Decrypt
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res =
      Hacl_NaCl_crypto_box_open_easy_afternm(got_plaintext.data(),
                                             test.ciphertext.data(),
                                             test.ciphertext.size(),
                                             test.nonce.data(),
                                             k.data());
    ASSERT_EQ(res, 0);
    EXPECT_EQ(test.plaintext, got_plaintext);
  }
}

TEST_P(NaClBoxSuite, SplitDetachedKAT)
{
  auto test = GetParam();

  bytes expected_tag =
    bytes(test.ciphertext.begin(),
          test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES);
  bytes expected_ciphertext =
    bytes(test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES,
          test.ciphertext.end());

  bytes k(HACL_NACL_CRYPTO_BOX_BEFORENMBYTES);
  uint32_t res = Hacl_NaCl_crypto_box_beforenm(
    k.data(), test.bob_pk.data(), test.alice_sk.data());
  EXPECT_EQ(res, 0);

  // Encrypt
  {
    bytes got_tag(HACL_NACL_CRYPTO_BOX_MACBYTES);
    bytes got_ciphertext(test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_detached_afternm(got_ciphertext.data(),
                                                         got_tag.data(),
                                                         test.plaintext.data(),
                                                         test.plaintext.size(),
                                                         test.nonce.data(),
                                                         k.data());
    ASSERT_EQ(res, 0);
    ASSERT_EQ(expected_tag, got_tag);
    ASSERT_EQ(expected_ciphertext, got_ciphertext);
  }

  // Decrypt
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res =
      Hacl_NaCl_crypto_box_open_detached_afternm(got_plaintext.data(),
                                                 expected_ciphertext.data(),
                                                 expected_tag.data(),
                                                 test.plaintext.size(),
                                                 test.nonce.data(),
                                                 k.data());
    ASSERT_EQ(res, 0);
    ASSERT_EQ(test.plaintext, got_plaintext);
  }
}

TEST_P(NaClBoxSuite, InvalidKAT)
{
  auto test = GetParam();

  bytes expected_tag =
    bytes(test.ciphertext.begin(),
          test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES);
  bytes expected_ciphertext =
    bytes(test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES,
          test.ciphertext.end());

  bytes bad_pk(test.bob_pk.size(), 0);

  // Bad Public Key (easy).
  {
    bytes got_ciphertext(HACL_NACL_CRYPTO_BOX_MACBYTES + test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_box_easy(got_ciphertext.data(),
                                             test.plaintext.data(),
                                             test.plaintext.size(),
                                             test.nonce.data(),
                                             bad_pk.data(),
                                             test.alice_sk.data());
    ASSERT_NE(res, 0);
  }

  // Bad Public Key (detached).
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res =
      Hacl_NaCl_crypto_box_open_detached(got_plaintext.data(),
                                         expected_ciphertext.data(),
                                         expected_tag.data(),
                                         test.plaintext.size(),
                                         test.nonce.data(),
                                         bad_pk.data(),
                                         test.alice_sk.data());
    ASSERT_NE(res, 0);
  }

  // Bitflip in tag (easy).
  {
    bytes got_plaintext(test.plaintext.size());
    bytes bad_ciphertext(test.ciphertext);
    bad_ciphertext[0] ^= 1;
    uint32_t res = Hacl_NaCl_crypto_box_open_easy(got_plaintext.data(),
                                                  bad_ciphertext.data(),
                                                  bad_ciphertext.size(),
                                                  test.nonce.data(),
                                                  test.bob_pk.data(),
                                                  test.alice_sk.data());
    ASSERT_NE(res, 0);
  }

  // Bitflip in tag (detached).
  {
    bytes got_plaintext(test.plaintext.size());
    bytes bad_tag(expected_tag);
    bad_tag[0] ^= 1;
    uint32_t res =
      Hacl_NaCl_crypto_box_open_detached(got_plaintext.data(),
                                         expected_ciphertext.data(),
                                         bad_tag.data(),
                                         test.plaintext.size(),
                                         test.nonce.data(),
                                         test.bob_pk.data(),
                                         test.alice_sk.data());
    ASSERT_NE(res, 0);
  }
}

// ----- NaCl Secret Box -------------------------------------------------------

typedef struct
{
  bytes key;
  bytes nonce;
  bytes plaintext;
  bytes ciphertext;
} SecretBoxTestCase;

class NaClSecretBoxSuite : public ::testing::TestWithParam<SecretBoxTestCase>
{};

TEST_P(NaClSecretBoxSuite, EasyKAT)
{
  auto test = GetParam();

  // Encrypt
  {
    bytes got_ciphertext(HACL_NACL_CRYPTO_BOX_MACBYTES + test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_secretbox_easy(got_ciphertext.data(),
                                                   test.plaintext.data(),
                                                   test.plaintext.size(),
                                                   test.nonce.data(),
                                                   test.key.data());
    ASSERT_EQ(res, 0);
    ASSERT_EQ(got_ciphertext, test.ciphertext);
  }

  // Decrypt
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_secretbox_open_easy(got_plaintext.data(),
                                                        test.ciphertext.data(),
                                                        test.ciphertext.size(),
                                                        test.nonce.data(),
                                                        test.key.data());
    ASSERT_EQ(res, 0);
    ASSERT_EQ(got_plaintext, test.plaintext);
  }
}

TEST_P(NaClSecretBoxSuite, EasyDetachedKAT)
{
  auto test = GetParam();

  bytes expected_tag =
    bytes(test.ciphertext.begin(),
          test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES);
  bytes expected_ciphertext =
    bytes(test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES,
          test.ciphertext.end());

  // Encrypt
  {
    bytes got_tag(HACL_NACL_CRYPTO_BOX_MACBYTES);
    bytes got_ciphertext(test.plaintext.size());
    uint32_t res = Hacl_NaCl_crypto_secretbox_detached(got_ciphertext.data(),
                                                       got_tag.data(),
                                                       test.plaintext.data(),
                                                       test.plaintext.size(),
                                                       test.nonce.data(),
                                                       test.key.data());
    ASSERT_EQ(res, 0);
    ASSERT_EQ(expected_tag, got_tag);
    ASSERT_EQ(expected_ciphertext, got_ciphertext);
  }

  // Decrypt
  {
    bytes got_plaintext(test.plaintext.size());
    uint32_t res =
      Hacl_NaCl_crypto_secretbox_open_detached(got_plaintext.data(),
                                               expected_ciphertext.data(),
                                               expected_tag.data(),
                                               test.plaintext.size(),
                                               test.nonce.data(),
                                               test.key.data());
    ASSERT_EQ(res, 0);
    ASSERT_EQ(test.plaintext, got_plaintext);
  }
}

TEST_P(NaClSecretBoxSuite, InvalidKAT)
{
  auto test = GetParam();

  bytes expected_tag =
    bytes(test.ciphertext.begin(),
          test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES);
  bytes expected_ciphertext =
    bytes(test.ciphertext.begin() + HACL_NACL_CRYPTO_BOX_MACBYTES,
          test.ciphertext.end());

  // Bitflip in tag (easy).
  {
    bytes got_plaintext(test.plaintext.size());
    bytes bad_ciphertext(test.ciphertext);
    bad_ciphertext[0] ^= 1;
    uint32_t res = Hacl_NaCl_crypto_secretbox_open_easy(got_plaintext.data(),
                                                        bad_ciphertext.data(),
                                                        bad_ciphertext.size(),
                                                        test.nonce.data(),
                                                        test.key.data());
    ASSERT_NE(res, 0);
  }

  // Bitflip in tag (detached).
  {
    bytes got_plaintext(test.plaintext.size());
    bytes bad_tag(expected_tag);
    bad_tag[0] ^= 1;
    uint32_t res =
      Hacl_NaCl_crypto_secretbox_open_detached(got_plaintext.data(),
                                               expected_ciphertext.data(),
                                               bad_tag.data(),
                                               test.plaintext.size(),
                                               test.nonce.data(),
                                               test.key.data());
    ASSERT_NE(res, 0);
  }
}

vector<BoxTestCase>
read_json_box(char* path)
{
  json tests_raw;
  ifstream file(path);
  file >> tests_raw;

  vector<BoxTestCase> tests;

  for (auto& test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    tests.push_back(BoxTestCase{
      .alice_sk = from_hex(test["alice_sk"]),
      .alice_pk = from_hex(test["alice_pk"]),
      .bob_sk = from_hex(test["bob_sk"]),
      .bob_pk = from_hex(test["bob_pk"]),
      .nonce = from_hex(test["nonce"]),
      .plaintext = from_hex(test["plaintext"]),
      .ciphertext = from_hex(test["ciphertext"]),
    });
  }

  return tests;
}

vector<SecretBoxTestCase>
read_json_secret_box(char* path)
{
  json tests_raw;
  ifstream file(path);
  file >> tests_raw;

  vector<SecretBoxTestCase> tests;

  for (auto& test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    tests.push_back(SecretBoxTestCase{
      .key = from_hex(test["key"]),
      .nonce = from_hex(test["nonce"]),
      .plaintext = from_hex(test["plaintext"]),
      .ciphertext = from_hex(test["ciphertext"]),
    });
  }

  return tests;
}

INSTANTIATE_TEST_SUITE_P(
  Box,
  NaClBoxSuite,
  ::testing::ValuesIn(read_json_box(const_cast<char*>("cryspen_box.json"))));

INSTANTIATE_TEST_SUITE_P(SecretBox,
                         NaClSecretBoxSuite,
                         ::testing::ValuesIn(read_json_secret_box(
                           const_cast<char*>("cryspen_secret_box.json"))));
