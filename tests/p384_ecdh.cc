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

#include "Hacl_P384.h"
#include "util.h"

using json = nlohmann::json;

// ANCHOR(DEFINE)
#define HACL_DH_P384_SECRETKEY_LEN 48
#define HACL_DH_P384_PUBLICKEY_LEN 96
#define HACL_DH_P384_SHARED_LEN 96
// ANCHOR_END(DEFINE)

TEST(ApiSuite, ApiTest)
{
  // ANCHOR(EXAMPLE)
  // Alice and Bob want to agree on a shared secret via X25519.

  // Thus, Alice needs a secret and public key ...
  uint8_t alice_sk[HACL_DH_P384_SECRETKEY_LEN];
  uint8_t alice_pk[HACL_DH_P384_PUBLICKEY_LEN];
  // Note: This function is not in HACL*.
  //       You need to bring your own random.
  generate_p384_keypair(alice_sk, alice_pk);

  // ... and Bob does as well.
  uint8_t bob_sk[HACL_DH_P384_SECRETKEY_LEN];
  uint8_t bob_pk[HACL_DH_P384_PUBLICKEY_LEN];
  // Note: This function is not in HACL*.
  //       You need to bring your own random.
  generate_p384_keypair(bob_sk, bob_pk);

  // Now, Alice and Bob exchange their public keys so that
  // Alice can compute her shared secret as ...
  uint8_t shared_alice[HACL_DH_P384_SHARED_LEN];
  bool res_alice = Hacl_P384_dh_responder(shared_alice, bob_pk, alice_sk);

  // ... and Bob can compute his shared secret as ...
  uint8_t shared_bob[HACL_DH_P384_SHARED_LEN];
  bool res_bob = Hacl_P384_dh_responder(shared_bob, alice_pk, bob_sk);

  // Now, both Alice and Bob should share the same secret value, i.e.,
  //
  //     `shared_alice` == `shared_bob`
  //
  // ... and can use this to derive, e.g., an encryption key.
  // ANCHOR_END(EXAMPLE)

  EXPECT_TRUE(memcmp(shared_alice, shared_bob, HACL_DH_P384_SHARED_LEN) == 0);
  EXPECT_TRUE(res_alice);
  EXPECT_TRUE(res_bob);
}

//=== Wycheproof tests ====

#define bytes std::vector<uint8_t>

typedef struct
{
  bytes public_key;
  bytes private_key;
  bytes shared;
  bool valid;
} TestCase;

std::vector<TestCase>
read_json()
{

  // Read JSON test vector
  std::string test_dir = "ecdh_secp384r1_ecpoint_test.json";
  std::ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();

    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto private_key = from_hex(test_case_value["private"]);
      auto public_key = from_hex(test_case_value["public"]);
      auto shared = from_hex(test_case_value["shared"]);
      auto result = test_case_value["result"];
      bool valid = result == "valid" || result == "acceptable";

      tests_out.push_back({ public_key, private_key, shared, valid });
    }
  }

  return tests_out;
}

class P384EcdhWycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(P384EcdhWycheproof, TryWycheproof)
{
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* private_key = const_cast<uint8_t*>(test_case.private_key.data());
  uint8_t* public_key = const_cast<uint8_t*>(test_case.public_key.data());

  // Convert public key first
  uint8_t plain_public_key[96] = { 0 };
  bool uncompressed_point = false;
  bool compressed_point = false;
  if (test_case.public_key.size() >= 97) {
    uncompressed_point =
      Hacl_P384_uncompressed_to_raw(public_key, plain_public_key);
  }
  if (!uncompressed_point && test_case.public_key.size() >= 48) {
    compressed_point =
      Hacl_P384_compressed_to_raw(public_key, plain_public_key);
    if (!compressed_point) printf("compressed_to_raw failed\n");

  }
  EXPECT_TRUE(uncompressed_point || compressed_point || !test_case.valid);
  // Convert the private key
  uint8_t plain_private_key[48] = { 0 };
  size_t sk_len = test_case.private_key.size();
  if (sk_len > 48) {
    sk_len = 48;
  }
  for (size_t i = 0; i < sk_len; i++) {
    plain_private_key[47 - i] =
      test_case.private_key[test_case.private_key.size() - 1 - i];
  }

  uint8_t computed_shared[96] = { 0 };
  Hacl_P384_dh_responder(computed_shared, plain_public_key, plain_private_key);
  if (test_case.valid) {
    EXPECT_EQ(std::vector<uint8_t>(computed_shared, computed_shared + 48),
              test_case.shared);
  } else {
    EXPECT_NE(std::vector<uint8_t>(computed_shared, computed_shared + 48),
              test_case.shared);
  }
}

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         P384EcdhWycheproof,
                         ::testing::ValuesIn(read_json()));
