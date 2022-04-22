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

#include "Hacl_P256.h"
#include "util.h"

using json = nlohmann::json;

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
  std::string test_dir = "ecdh_secp256r1_ecpoint_test.json";
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

class P256EcdhWycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(P256EcdhWycheproof, TryWycheproof)
{
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* private_key = const_cast<uint8_t*>(test_case.private_key.data());
  uint8_t* public_key = const_cast<uint8_t*>(test_case.public_key.data());

  // Convert public key first
  uint8_t plain_public_key[64] = { 0 };
  bool uncompressed_point = false;
  bool compressed_point = false;
  if (test_case.public_key.size() >= 65) {
    uncompressed_point =
      Hacl_P256_uncompressed_to_raw(public_key, plain_public_key);
  }
  if (!uncompressed_point && test_case.public_key.size() >= 32) {
    compressed_point =
      Hacl_P256_compressed_to_raw(public_key, plain_public_key);
  }
  EXPECT_TRUE(uncompressed_point || compressed_point || !test_case.valid);

  // Convert the private key
  uint8_t plain_private_key[32] = { 0 };
  size_t sk_len = test_case.private_key.size();
  if (sk_len > 32) {
    sk_len = 32;
  }
  for (size_t i = 0; i < sk_len; i++) {
    plain_private_key[31 - i] =
      test_case.private_key[test_case.private_key.size() - 1 - i];
  }

  uint8_t computed_shared[64] = { 0 };
  Hacl_P256_dh_responder(computed_shared, plain_public_key, plain_private_key);
  if (test_case.valid) {
    EXPECT_EQ(std::vector<uint8_t>(computed_shared, computed_shared + 32),
              test_case.shared);
  } else {
    EXPECT_NE(std::vector<uint8_t>(computed_shared, computed_shared + 32),
              test_case.shared);
  }
}

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         P256EcdhWycheproof,
                         ::testing::ValuesIn(read_json()));
