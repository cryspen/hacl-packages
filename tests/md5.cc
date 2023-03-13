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

#include "EverCrypt_Hash.h"
#include "Hacl_Hash_Base.h"
#include "Hacl_Hash_MD5.h"
#include "Hacl_Spec.h"
#include "evercrypt.h"
#include "util.h"

using json = nlohmann::json;

typedef struct
{
  bytes message;
  bytes hash;
} TestCase;

class Md5Suite : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Md5Suite, TestCase)
{
  auto test = GetParam();

  bytes got_hash = std::vector<uint8_t>(16);
  Hacl_Hash_MD5_legacy_hash0(
    got_hash.data(), test.message.data(), test.message.size());

  EXPECT_EQ(got_hash, test.hash);
}

// ----- EverCrypt -------------------------------------------------------------

typedef EverCryptSuite<TestCase> EverCryptSuiteTestCase;

TEST_P(EverCryptSuiteTestCase, HashTest)
{
  EverCryptConfig config;
  TestCase test;
  tie(config, test) = this->GetParam();

  {
    bytes got_digest(Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_MD5));

    EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_MD5,
                                    got_digest.data(),
                                    test.message.data(),
                                    test.message.size());

    ASSERT_EQ(test.hash, got_digest);
  }

  {
    bytes got_digest(Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_MD5));

    EverCrypt_Hash_Incremental_hash_state* state =
      EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_MD5);
    EverCrypt_Hash_Incremental_reset(state);
    EverCrypt_Hash_Incremental_update(
      state, test.message.data(), test.message.size());
    EverCrypt_Hash_Incremental_digest(state, got_digest.data());
    EverCrypt_Hash_Incremental_free(state);

    ASSERT_EQ(test.hash, got_digest);
  }
}

// -----------------------------------------------------------------------------

std::vector<TestCase>
read_json(std::string path)
{
  json tests_raw;
  std::ifstream file(path);
  file >> tests_raw;

  std::vector<TestCase> tests;

  for (auto& test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    std::string message_str = test["message"];
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    bytes hash = from_hex(test["hash"]);

    tests.push_back(TestCase{
      .message = message,
      .hash = hash,
    });
  }

  return tests;
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(Rfc1231,
                         Md5Suite,
                         ::testing::ValuesIn(read_json("rfc1321.json")));

INSTANTIATE_TEST_SUITE_P(Cryspen,
                         Md5Suite,
                         ::testing::ValuesIn(read_json("cryspen_md5.json")));

// ----- EverCrypt -------------------------------------------------------------

// There is no hardware support for MD5.
vector<EverCryptConfig>
generate_md5_configs()
{
  vector<EverCryptConfig> configs;

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
    .disable_shaext = false,
    .disable_sse = false,
  });

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  Rfc1231,
  EverCryptSuiteTestCase,
  ::testing::Combine(::testing::ValuesIn(generate_md5_configs()),
                     ::testing::ValuesIn(read_json("rfc1321.json"))));

INSTANTIATE_TEST_SUITE_P(
  Cryspen,
  EverCryptSuiteTestCase,
  ::testing::Combine(::testing::ValuesIn(generate_md5_configs()),
                     ::testing::ValuesIn(read_json("cryspen_md5.json"))));
