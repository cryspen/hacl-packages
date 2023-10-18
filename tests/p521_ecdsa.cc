/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <nlohmann/json.hpp>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "Hacl_P521.h"
#include "util.h"

// ANCHOR(EXAMPLE DEFINE)
// Note: HACL Packages will provide these in a later version.
#define HACL_SIGNATURE_ECDSA_P521_SECRETKEY_LEN 66
#define HACL_SIGNATURE_ECDSA_P521_PUBLICKEY_LEN 132

#define HACL_SIGNATURE_ECDSA_P521_PUBLICKEY_COMPRESSED_LEN 67
#define HACL_SIGNATURE_ECDSA_P521_PUBLICKEY_UNCOMPRESSED_LEN 133

#define HACL_SIGNATURE_ECDSA_P521_NONCE_LEN 66

#define HACL_SIGNATURE_ECDSA_P521_SIGNATURE_LEN 132
// ANCHOR_END(EXAMPLE DEFINE)

using json = nlohmann::json;
using namespace std;

// -----------------------------------------------------------------------------

TEST(ApiSuite, ApiTest)
{
  // ANCHOR(EXAMPLE)
  // We want to sign and verify a message.

  // Message
  const char* message = "Hello, World!";
  uint32_t message_size = strlen(message);

  // Keys
  uint8_t sk[HACL_SIGNATURE_ECDSA_P521_SECRETKEY_LEN];
  uint8_t pk[HACL_SIGNATURE_ECDSA_P521_PUBLICKEY_LEN];

  // Note: This function is not in HACL*.
  //       You need to bring your own keys.
  generate_p521_keypair(sk, pk);

  // Nonce
  uint8_t nonce[HACL_SIGNATURE_ECDSA_P521_NONCE_LEN];

  // Signature
  uint8_t signature[HACL_SIGNATURE_ECDSA_P521_SIGNATURE_LEN];

  // Sign
  bool res_sign = Hacl_P521_ecdsa_sign_p521_sha2(
    signature, message_size, (uint8_t*)message, sk, nonce);

  if (!res_sign) {
    // Error
  }

  // Verify
  bool res_verify = Hacl_P521_ecdsa_verif_p521_sha2(
    message_size, (uint8_t*)message, pk, signature, signature + 66);

  if (!res_verify) {
    // Error
  }
  // ANCHOR_END(EXAMPLE)

  EXPECT_TRUE(res_sign);
  EXPECT_TRUE(res_verify);
}

// -----------------------------------------------------------------------------

//=== Wycheproof tests ====

typedef struct
{
  bytes public_key;
  string sha;
  bytes msg;
  bytes sig;
  bool valid;
} TestCase;

std::vector<TestCase>
read_json(string path)
{
  std::ifstream json_test_file(path);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& group_raw : test_vectors["testGroups"].items()) {
    auto group = group_raw.value();

    // Read the key
    auto key = group["key"];
    auto public_key = from_hex(key["uncompressed"]);
    auto sha = group["sha"];

    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();
      auto msg = from_hex(test["msg"]);
      auto sig = from_hex(test["sig"]);
      auto result = test["result"];
      bool valid = result == "valid" || result == "acceptable";

      tests_out.push_back({ public_key, sha, msg, sig, valid });
    }
  }

  return tests_out;
}

class P521EcdsaWycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(P521EcdsaWycheproof, TryWycheproof)
{
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* public_key = const_cast<uint8_t*>(test_case.public_key.data());
  uint8_t* msg = const_cast<uint8_t*>(test_case.msg.data());

  // Convert public key first
  uint8_t plain_public_key[132] = { 0 };
  bool uncompressed_point = false;
  bool compressed_point = false;
  if (test_case.public_key.size() >= 133) {
    uncompressed_point =
      Hacl_P521_uncompressed_to_raw(public_key, plain_public_key);
  }
  if (!uncompressed_point && test_case.public_key.size() >= 66) {
    compressed_point =
      Hacl_P521_compressed_to_raw(public_key, plain_public_key);
  }
  EXPECT_TRUE(uncompressed_point || compressed_point || !test_case.valid);

  // Check the way back from raw -> (un)compressed.
  if (compressed_point) {
    bytes got_compressed(test_case.public_key.size());
    Hacl_P521_raw_to_compressed(plain_public_key, got_compressed.data());
    ASSERT_EQ(test_case.public_key, got_compressed);
  } else if (uncompressed_point) {
    bytes got_uncompressed(test_case.public_key.size());
    Hacl_P521_raw_to_uncompressed(plain_public_key, got_uncompressed.data());
    ASSERT_EQ(test_case.public_key, got_uncompressed);
  } else {
    FAIL() << "Point should have been either compressed or uncompressed.";
  }

  // Parse DER signature.
  // FIXME: This should really be in the HACL* libraray.
  //        The parsing here is opportunistic and not robust.
  size_t sig_pointer = 0;
  if (test_case.valid) {
    EXPECT_TRUE(test_case.sig.size() >= 2);
  }
  bytes r, s;

  if (test_case.sig.size() > 2) {
    if (test_case.valid) {
      size_t pos = 0;
      EXPECT_EQ(test_case.sig[pos++], 0x30); // Sequence tag
      auto der_length = test_case.sig[pos++];
      EXPECT_FALSE(der_length & 0x80);
      EXPECT_EQ(test_case.sig[pos++], 0x02); // Integer
      auto x_length = test_case.sig[pos++];
      r = bytes(&test_case.sig[pos], &test_case.sig[pos] + x_length);
      pos += x_length;
      EXPECT_EQ(test_case.sig[pos++], 0x02); // Integer
      auto y_length = test_case.sig[pos++];
      s = bytes(&test_case.sig[pos], &test_case.sig[pos] + y_length);
      pos += y_length;
      EXPECT_EQ(pos, der_length + 2);
    }
  }
  if (r.size() != 0 && s.size() != 0) {
    // Removing leading 0s and make r and s 32 bytes each
    while (r[0] == 0x00) {
      r.erase(r.begin());
    }
    while (r.size() < 66) {
      r.insert(r.begin(), 0);
    }
    while (s[0] == 0x00) {
      s.erase(s.begin());
    }
    while (s.size() < 66) {
      s.insert(s.begin(), 0);
    }
    EXPECT_EQ(66, r.size());
    EXPECT_EQ(66, s.size());

    // Due to https://github.com/project-everest/hacl-star/issues/327
    // we fake the msg pointer here for now if it's NULL.
    if (!msg) {
      msg = r.data(); // the length is 0 so we never do anything with this.
      EXPECT_EQ(0, test_case.msg.size());
    }

    if (test_case.sha == "SHA-512") {
      EXPECT_EQ(
        test_case.valid,
        Hacl_P521_ecdsa_verif_p521_sha512(
          test_case.msg.size(), msg, plain_public_key, r.data(), s.data()));
    } else {
      FAIL() << "Unexpected value.";
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
  WycheproofSha512,
  P521EcdsaWycheproof,
  ::testing::ValuesIn(read_json("ecdsa_secp521r1_sha512_test.json")));
