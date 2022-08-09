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

#include "Hacl_Hash_SHA2.h"
#include "Hacl_Streaming_SHA2.h"

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

class Sha2KAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Sha2KAT, TryKAT)
{
  auto test_case = GetParam();

  bytes digest(test_case.md.size(), 0);
  if (test_case.md.size() == 224 / 8) {
    Hacl_Hash_SHA2_hash_224(
      test_case.msg.data(), test_case.msg.size(), digest.data());
  } else if (test_case.md.size() == 256 / 8) {
    Hacl_Hash_SHA2_hash_256(
      test_case.msg.data(), test_case.msg.size(), digest.data());
  } else if (test_case.md.size() == 384 / 8) {
    Hacl_Hash_SHA2_hash_384(
      test_case.msg.data(), test_case.msg.size(), digest.data());
  } else if (test_case.md.size() == 512 / 8) {
    Hacl_Hash_SHA2_hash_512(
      test_case.msg.data(), test_case.msg.size(), digest.data());
  }

  EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                  << bytes_to_hex(digest) << std::endl;

  // Streaming
  {
    bytes digest(test_case.md.size(), 0);

    if (test_case.md.size() == 224 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_224* state =
        Hacl_Streaming_SHA2_create_in_224();
      Hacl_Streaming_SHA2_init_224(state);

      // Update
      Hacl_Streaming_SHA2_update_224(
        state, test_case.msg.data(), test_case.msg.size());

      // Finish
      Hacl_Streaming_SHA2_finish_224(state, digest.data());
      Hacl_Streaming_SHA2_free_224(state);
    } else if (test_case.md.size() == 256 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_224* state =
        Hacl_Streaming_SHA2_create_in_256();
      Hacl_Streaming_SHA2_init_256(state);

      // Update
      Hacl_Streaming_SHA2_update_256(
        state, test_case.msg.data(), test_case.msg.size());

      // Finish
      Hacl_Streaming_SHA2_finish_256(state, digest.data());
      Hacl_Streaming_SHA2_free_256(state);
    } else if (test_case.md.size() == 384 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_384* state =
        Hacl_Streaming_SHA2_create_in_384();
      Hacl_Streaming_SHA2_init_384(state);

      // Update
      Hacl_Streaming_SHA2_update_384(
        state, test_case.msg.data(), test_case.msg.size());

      // Finish
      Hacl_Streaming_SHA2_finish_384(state, digest.data());
      Hacl_Streaming_SHA2_free_384(state);
    } else if (test_case.md.size() == 512 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_512* state =
        Hacl_Streaming_SHA2_create_in_512();
      Hacl_Streaming_SHA2_init_512(state);

      // Update
      Hacl_Streaming_SHA2_update_512(
        state, test_case.msg.data(), test_case.msg.size());

      // Finish
      Hacl_Streaming_SHA2_finish_512(state, digest.data());
      Hacl_Streaming_SHA2_free_512(state);
    }

    EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest) << std::endl;
  }

  // TODO: Evercrypt
}

INSTANTIATE_TEST_SUITE_P(
  CryspenSha224,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("cryspen_sha2_224.json"))));

INSTANTIATE_TEST_SUITE_P(
  CryspenSha256,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("cryspen_sha2_256.json"))));

INSTANTIATE_TEST_SUITE_P(
  CryspenSha384,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("cryspen_sha2_384.json"))));

INSTANTIATE_TEST_SUITE_P(
  CryspenSha512,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("cryspen_sha2_512.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha224ShortKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha224-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha224LongKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha224-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha256ShortKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha256-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha256LongKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha256-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha384ShortKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha384-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha384LongKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha384-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha512ShortKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha512-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha512LongKAT,
  Sha2KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha512-short.json"))));
