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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Hacl_Hash_SHA2.h"
#include "Hacl_K256_ECDSA.h"
#include "util.h"

using json = nlohmann::json;

#define bytes std::vector<uint8_t>

typedef struct
{
  bytes public_key;
  bytes msg;
  bytes sig;
  bool valid;
} TestCase;

std::vector<TestCase>
read_json()
{

  // Read JSON test vector
  std::string test_dir = "ecdsa_secp256k1_sha256_test.json";
  std::ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();

    // Read the key
    auto key = test_value["key"];
    auto public_key = from_hex(key["uncompressed"]);

    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto msg = from_hex(test_case_value["msg"]);
      auto sig = from_hex(test_case_value["sig"]);
      auto result = test_case_value["result"];
      bool valid = result == "valid" || result == "acceptable";

      tests_out.push_back({ public_key, msg, sig, valid });
    }
  }

  return tests_out;
}

class P256EcdsaWycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(P256EcdsaWycheproof, TryWycheproof)
{
  const TestCase& test_case(GetParam());

  //   printf("pk: %s\n", bytes_to_hex(test_case.public_key).c_str());
  //   printf("msg: %s\n", bytes_to_hex(test_case.msg).c_str());
  // Stupid const
  uint8_t* public_key = const_cast<uint8_t*>(test_case.public_key.data());
  uint8_t* msg = const_cast<uint8_t*>(test_case.msg.data());

  // Convert public key first
  uint8_t plain_public_key[64] = { 0 };
  bool uncompressed_point = false;
  bool compressed_point = false;
  if (test_case.public_key.size() >= 65) {
    uncompressed_point = Hacl_K256_ECDSA_public_key_uncompressed_to_raw(
      plain_public_key, public_key);
  }
  if (!uncompressed_point && test_case.public_key.size() >= 32) {
    compressed_point = Hacl_K256_ECDSA_public_key_compressed_to_raw(
      plain_public_key, public_key);
  }
  EXPECT_TRUE(uncompressed_point || compressed_point || !test_case.valid);

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
    while (r.size() < 32) {
      r.insert(r.begin(), 0);
    }
    while (s[0] == 0x00) {
      s.erase(s.begin());
    }
    while (s.size() < 32) {
      s.insert(s.begin(), 0);
    }
    EXPECT_EQ(32, r.size());
    EXPECT_EQ(32, s.size());

    // Concat r||s because the API is awesome.
    bytes rs;
    rs.insert(rs.end(), r.begin(), r.end());
    rs.insert(rs.end(), s.begin(), s.end());

    // TODO: Only testing non low-S normalized here for now.
    uint8_t digest[32] = { 0 };
    Hacl_Hash_SHA2_hash_256(msg, test_case.msg.size(), &digest[0]);
    EXPECT_EQ(test_case.valid,
              Hacl_K256_ECDSA_ecdsa_verify_hashed_msg(
                &digest[0], plain_public_key, rs.data()));
  }
}

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         P256EcdsaWycheproof,
                         ::testing::ValuesIn(read_json()));
