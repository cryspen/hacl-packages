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

#include "Hacl_Hash_Base.h"
#include "Hacl_Hash_MD5.h"
#include "Hacl_Spec.h"
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
  Hacl_Hash_MD5_legacy_hash(
    test.message.data(), test.message.size(), got_hash.data());

  EXPECT_EQ(got_hash, test.hash);
}

std::vector<TestCase>
read_json(char* path)
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

INSTANTIATE_TEST_SUITE_P(
  Rfc1231,
  Md5Suite,
  ::testing::ValuesIn(read_json(const_cast<char*>("rfc1321.json"))));
