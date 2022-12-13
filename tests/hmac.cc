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

#include "EverCrypt_HMAC.h"
#include "Hacl_HMAC.h"
#include "evercrypt.h"
#include "hacl-cpu-features.h"
#include "util.h"

using json = nlohmann::json;

// ANCHOR(DEFINE)
// Note: HACL Packages will provide these in a later version.
#define HACL_MAC_HMAC_BLAKE2B_KEY_LEN_MAX 128
#define HACL_MAC_HMAC_BLAKE2S_KEY_LEN_MAX 64
#define HACL_MAC_HMAC_SHA2_256_KEY_LEN_MAX 64
#define HACL_MAC_HMAC_SHA2_384_KEY_LEN_MAX 128
#define HACL_MAC_HMAC_SHA2_512_KEY_LEN_MAX 128
#define HACL_MAC_HMAC_SHA1_KEY_LEN_MAX 64

#define HACL_MAC_HMAC_BLAKE2B_TAG_LEN 64
#define HACL_MAC_HMAC_BLAKE2S_TAG_LEN 32
#define HACL_MAC_HMAC_SHA2_256_TAG_LEN 32
#define HACL_MAC_HMAC_SHA2_384_TAG_LEN 48
#define HACL_MAC_HMAC_SHA2_512_TAG_LEN 64
#define HACL_MAC_HMAC_SHA1_TAG_LEN 20
// ANCHOR_END(DEFINE)

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

TEST(ApiSuite, ApiTest)
{
  // Documentation.
  // Lines after ANCHOR and before ANCHOR_END are used in documentation.
  {
    // ANCHOR(EXAMPLE)
    const char* data = "Hello, World!";
    uint32_t data_len = strlen(data);

    uint8_t key[HACL_MAC_HMAC_SHA2_256_KEY_LEN_MAX];
    // Note: This function is not from HACL*.
    //       You need to bring your own random.
    generate_sha2_256_hmac_key(key);

    uint8_t dst[HACL_MAC_HMAC_SHA2_256_TAG_LEN];

    Hacl_HMAC_compute_sha2_256(
      dst, key, HACL_MAC_HMAC_SHA2_256_KEY_LEN_MAX, (uint8_t*)data, data_len);
    // ANCHOR_END(EXAMPLE)

    bytes expected_digest = from_hex(
      "097015ddbdb0c43117c9b9df37858530f119069ce0418b7b12768a4dfe76ab90");

    EXPECT_EQ(strncmp((char*)dst,
                      (char*)expected_digest.data(),
                      HACL_MAC_HMAC_SHA2_256_TAG_LEN),
              0);
  }
}

std::vector<TestCase>
read_json(string path, size_t full_size)
{
  std::ifstream json_test_file(path);
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

std::vector<TestCase>
read_cavp_json(string test_dir)
{
  std::ifstream file(test_dir);
  json tests_raw;
  file >> tests_raw;

  std::vector<TestCase> tests;

  for (auto test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    bytes key = from_hex(test["Key"]);
    size_t key_size = test["Klen"];
    bytes msg = from_hex(test["Msg"]);
    bytes tag = from_hex(test["Mac"]);
    size_t tag_size = test["Tlen"];
    size_t full_size = test["L"];

    tests.push_back(TestCase{
      .key = key,
      .key_size = key_size * 8,
      .msg = msg,
      .tag = tag,
      .tag_size = tag_size * 8,
      .full_size = full_size,
      .valid = true,
    });
  }

  return tests;
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
  } else if (test_case.full_size == 28) {
    std::cout << "Skipping \"full_size=" << test_case.full_size << "\""
              << std::endl;
    return;
  } else if (test_case.full_size == 32) {
    Hacl_HMAC_compute_sha2_256(
      tag.data(), key, test_case.key.size(), msg, test_case.msg.size());
  } else if (test_case.full_size == 48) {
    Hacl_HMAC_compute_sha2_384(
      tag.data(), key, test_case.key.size(), msg, test_case.msg.size());
  } else if (test_case.full_size == 64) {
    Hacl_HMAC_compute_sha2_512(
      tag.data(), key, test_case.key.size(), msg, test_case.msg.size());
  } else {
    FAIL() << "Unsupported \"full_size\" (" << test_case.full_size << ")";
  }

  // XXX: Manually truncate the tag ...
  tag.resize(test_case.tag.size());

  std::cout << "Test: " << test_case.key_size << std::endl;

  if (test_case.valid) {
    EXPECT_EQ(tag, test_case.tag) << bytes_to_hex(tag) << std::endl
                                  << bytes_to_hex(test_case.tag) << std::endl;
  } else {
    EXPECT_NE(tag, test_case.tag);
  }
}

// ----- EverCrypt -------------------------------------------------------------

typedef EverCryptSuite<TestCase> HMACEverCryptSuite;

TEST_P(HMACEverCryptSuite, KAT)
{
  EverCryptConfig config;
  TestCase test;
  tie(config, test) = this->GetParam();

  EXPECT_EQ(test.key_size >> 3, test.key.size());
  EXPECT_EQ(test.tag_size >> 3, test.tag.size());

  bytes got_tag(test.full_size);
  if (test.full_size == 20) {
    ASSERT_TRUE(EverCrypt_HMAC_is_supported_alg(Spec_Hash_Definitions_SHA1));
    EverCrypt_HMAC_compute(Spec_Hash_Definitions_SHA1,
                           got_tag.data(),
                           test.key.data(),
                           test.key.size(),
                           test.msg.data(),
                           test.msg.size());
  } else if (test.full_size == 28) {
    std::cout << "Skipping \"full_size=" << test.full_size << "\"" << std::endl;
    return;
  } else if (test.full_size == 32) {
    ASSERT_TRUE(
      EverCrypt_HMAC_is_supported_alg(Spec_Hash_Definitions_SHA2_256));
    EverCrypt_HMAC_compute(Spec_Hash_Definitions_SHA2_256,
                           got_tag.data(),
                           test.key.data(),
                           test.key.size(),
                           test.msg.data(),
                           test.msg.size());
  } else if (test.full_size == 48) {
    ASSERT_TRUE(
      EverCrypt_HMAC_is_supported_alg(Spec_Hash_Definitions_SHA2_384));
    EverCrypt_HMAC_compute(Spec_Hash_Definitions_SHA2_384,
                           got_tag.data(),
                           test.key.data(),
                           test.key.size(),
                           test.msg.data(),
                           test.msg.size());
  } else if (test.full_size == 64) {
    ASSERT_TRUE(
      EverCrypt_HMAC_is_supported_alg(Spec_Hash_Definitions_SHA2_512));
    EverCrypt_HMAC_compute(Spec_Hash_Definitions_SHA2_512,
                           got_tag.data(),
                           test.key.data(),
                           test.key.size(),
                           test.msg.data(),
                           test.msg.size());
  } else {
    FAIL() << "Unsupported \"full_size\" (" << test.full_size << ")";
  }

  // XXX: Manually truncate the got_tag ...
  got_tag.resize(test.tag.size());

  if (test.valid) {
    EXPECT_EQ(got_tag, test.tag) << bytes_to_hex(got_tag) << std::endl
                                 << bytes_to_hex(test.tag) << std::endl;
  } else {
    EXPECT_NE(got_tag, test.tag);
  }
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(HmacSha1Kat,
                         HmacKAT,
                         ::testing::ValuesIn(read_json("hmac_sha1_test.json",
                                                       20)));

INSTANTIATE_TEST_SUITE_P(HmacSha256Kat,
                         HmacKAT,
                         ::testing::ValuesIn(read_json("hmac_sha256_test.json",
                                                       32)));
INSTANTIATE_TEST_SUITE_P(HmacSha384Kat,
                         HmacKAT,
                         ::testing::ValuesIn(read_json("hmac_sha384_test.json",
                                                       48)));
INSTANTIATE_TEST_SUITE_P(HmacSha512Kat,
                         HmacKAT,
                         ::testing::ValuesIn(read_json("hmac_sha512_test.json",
                                                       64)));

INSTANTIATE_TEST_SUITE_P(CAVP,
                         HmacKAT,
                         ::testing::ValuesIn(read_cavp_json("CAVP_HMAC.json")));

// ----- EverCrypt -------------------------------------------------------------

// Portable (depends on hash) --> sha1, sha2 --> shaext
vector<EverCryptConfig>
generate_hmac_configs()
{
  vector<EverCryptConfig> configs;

  for (uint32_t i = 0; i < 2; ++i) {
    configs.push_back(EverCryptConfig{
      .disable_adx = false,
      .disable_aesni = false,
      .disable_avx = false,
      .disable_avx2 = false,
      .disable_avx512 = false,
      .disable_bmi2 = false,
      .disable_movbe = false,
      .disable_pclmulqdq = false,
      .disable_rdrand = false,
      .disable_shaext = (i & 1) != 0,
      .disable_sse = false,
    });
  }

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  HmacSha1Kat,
  HMACEverCryptSuite,
  ::testing::Combine(::testing::ValuesIn(generate_hmac_configs()),
                     ::testing::ValuesIn(read_json("hmac_sha1_test.json",
                                                   20))));

INSTANTIATE_TEST_SUITE_P(
  HmacSha256Kat,
  HMACEverCryptSuite,
  ::testing::Combine(::testing::ValuesIn(generate_hmac_configs()),
                     ::testing::ValuesIn(read_json("hmac_sha256_test.json",
                                                   32))));

INSTANTIATE_TEST_SUITE_P(
  HmacSha384Kat,
  HMACEverCryptSuite,
  ::testing::Combine(::testing::ValuesIn(generate_hmac_configs()),
                     ::testing::ValuesIn(read_json("hmac_sha384_test.json",
                                                   48))));

INSTANTIATE_TEST_SUITE_P(
  HmacSha512Kat,
  HMACEverCryptSuite,
  ::testing::Combine(::testing::ValuesIn(generate_hmac_configs()),
                     ::testing::ValuesIn(read_json("hmac_sha512_test.json",
                                                   64))));

INSTANTIATE_TEST_SUITE_P(
  CAVP,
  HMACEverCryptSuite,
  ::testing::Combine(::testing::ValuesIn(generate_hmac_configs()),
                     ::testing::ValuesIn(read_cavp_json("CAVP_HMAC.json"))));
