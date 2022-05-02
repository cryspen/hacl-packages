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

#include "Hacl_SHA3.h"

#include "config.h"
#include "util.h"

using json = nlohmann::json;

#define bytes std::vector<uint8_t>

typedef struct
{
  bytes msg;
  bytes md;
} TestCase;

std::vector<TestCase>
read_json(char* test_file)
{
  // Read JSON test vector
  std::ifstream json_test_file(test_file);
  nlohmann::json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read tests
  for (auto& test : test_vectors.items()) {
    auto test_value = test.value();
    auto msg = from_hex(test_value["msg"]);
    auto md = from_hex(test_value["md"]);
    tests_out.push_back({ msg, md });
  }

  return tests_out;
}

class Sha3KAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Sha3KAT, TryKAT)
{
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* msg = const_cast<uint8_t*>(test_case.msg.data());

  bytes digest(test_case.md.size(), 0);
  if (test_case.md.size() == 32) {
    Hacl_SHA3_sha3_256(test_case.msg.size(), msg, digest.data());
  } else if (test_case.md.size() == 48) {
    Hacl_SHA3_sha3_384(test_case.msg.size(), msg, digest.data());
  } else if (test_case.md.size() == 64) {
    Hacl_SHA3_sha3_512(test_case.msg.size(), msg, digest.data());
  }

  EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                  << bytes_to_hex(digest) << std::endl;

  // TODO: Evercrypt
}

INSTANTIATE_TEST_SUITE_P(
  Sha3_256ShortKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-256-short.json"))));
INSTANTIATE_TEST_SUITE_P(
  Sha3_256LongKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-256-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_384ShortKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-384-short.json"))));
INSTANTIATE_TEST_SUITE_P(
  Sha3_384LongKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-384-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_512ShortKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-512-short.json"))));
INSTANTIATE_TEST_SUITE_P(
  Sha3_512LongKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-512-long.json"))));
