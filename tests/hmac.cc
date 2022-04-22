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

#include "hacl-cpu-features.h"

#include "EverCrypt_HMAC.h"
#include "Hacl_HMAC.h"

#include "util.h"

using json = nlohmann::json;

#define bytes std::vector<uint8_t>

typedef struct
{
  bytes key;
  size_t key_size;
  bytes msg;
  bytes tag;
  size_t tag_size;
  size_t full_size;
  bool valid;
} TestCase;

std::vector<TestCase>
read_json(char* test_dir, size_t full_size)
{

  // Read JSON test vector
  std::ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();
    auto tag_size = test_value["tagSize"];
    auto key_size = test_value["keySize"];
    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto key = from_hex(test_case_value["key"]);
      auto msg = from_hex(test_case_value["msg"]);
      auto tag = from_hex(test_case_value["tag"]);
      auto result = test_case_value["result"];
      bool valid = result == "valid";

      tests_out.push_back(
        { key, key_size, msg, tag, tag_size, full_size, valid });
    }
  }

  return tests_out;
}

class HmacKAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(HmacKAT, TryKAT)
{
  const TestCase& test_case(GetParam());

  EXPECT_EQ(test_case.key_size >> 3, test_case.key.size());
  EXPECT_EQ(test_case.tag_size >> 3, test_case.tag.size());

  // Stupid const
  uint8_t* msg = const_cast<uint8_t*>(test_case.msg.data());
  uint8_t* key = const_cast<uint8_t*>(test_case.key.data());

  bytes tag(test_case.full_size, 0);
  if (test_case.full_size == 20) {
    Hacl_HMAC_legacy_compute_sha1(
      tag.data(), key, test_case.key.size(), msg, test_case.msg.size());
  } else if (test_case.full_size == 32) {
    Hacl_HMAC_compute_sha2_256(
      tag.data(), key, test_case.key.size(), msg, test_case.msg.size());
  } else if (test_case.full_size == 48) {
    Hacl_HMAC_compute_sha2_384(
      tag.data(), key, test_case.key.size(), msg, test_case.msg.size());
  } else if (test_case.full_size == 64) {
    Hacl_HMAC_compute_sha2_512(
      tag.data(), key, test_case.key.size(), msg, test_case.msg.size());
  }
  // XXX: Manually truncate the tag ...
  tag.resize(test_case.tag.size());
  if (test_case.valid) {
    EXPECT_EQ(tag, test_case.tag) << bytes_to_hex(tag) << std::endl
                                  << bytes_to_hex(test_case.tag) << std::endl;
  } else {
    EXPECT_NE(tag, test_case.tag);
  }

  // TODO: Evercrypt
}

INSTANTIATE_TEST_SUITE_P(
  HmacSha1Kat,
  HmacKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("hmac_sha1_test.json"), 20)));
INSTANTIATE_TEST_SUITE_P(
  HmacSha256Kat,
  HmacKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("hmac_sha256_test.json"),
                                32)));
INSTANTIATE_TEST_SUITE_P(
  HmacSha384Kat,
  HmacKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("hmac_sha384_test.json"),
                                48)));
INSTANTIATE_TEST_SUITE_P(
  HmacSha512Kat,
  HmacKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("hmac_sha512_test.json"),
                                64)));
