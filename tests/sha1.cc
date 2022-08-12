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

#include "Hacl_Streaming_SHA1.h"

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

class Sha1 : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Sha1, KAT)
{
  auto test = GetParam();

  bytes digest(test.md.size());

  // Init
  Hacl_Streaming_SHA2_state_sha2_224* state =
    Hacl_Streaming_SHA1_legacy_create_in_sha1();
  Hacl_Streaming_SHA1_legacy_init_sha1(state);

  // Update
  Hacl_Streaming_SHA1_legacy_update_sha1(
    state, test.msg.data(), test.msg.size());

  // Finish
  Hacl_Streaming_SHA1_legacy_finish_sha1(state, digest.data());
  Hacl_Streaming_SHA1_legacy_free_sha1(state);

  EXPECT_EQ(test.md, digest) << bytes_to_hex(test.md) << std::endl
                             << bytes_to_hex(digest) << std::endl;
}

INSTANTIATE_TEST_SUITE_P(
  Sha1Cryspen,
  Sha1,
  ::testing::ValuesIn(read_json(const_cast<char*>("cryspen_sha1.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPShort,
  Sha1,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha1-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPLong,
  Sha1,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha1-long.json"))));
