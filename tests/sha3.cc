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
#include <string.h>

#include "Hacl_Hash_SHA3.h"

#include "config.h"
#include "util.h"

using json = nlohmann::json;

// ANCHOR(example define)
// Note: HACL Packages will provide this (or a similar) define in a later
// version.
#define HACL_HASH_SHA3_256_DIGEST_LENGTH 32
// ANCHOR_END(example define)

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

TEST(ApiSuite, ApiTest)
{
  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // START OneShot
    // This example uses SHA3-256.
    //

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    uint8_t digest[HACL_HASH_SHA3_256_DIGEST_LENGTH];

    Hacl_SHA3_sha3_256(message_size, (uint8_t*)message, digest);
    // END OneShot

    bytes expected_digest = from_hex(
      "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef");

    EXPECT_EQ(strncmp((char*)digest,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
  }

  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // ANCHOR(streaming)
    // This example shows how to hash the byte sequence "Hello, World!" in two
    // chunks. As a bonus, it also shows how to obtain intermediate results by
    // calling `finish` more than once.

    const char* chunk_1 = "Hello, ";
    const char* chunk_2 = "World!";
    uint32_t chunk_1_size = strlen(chunk_1);
    uint32_t chunk_2_size = strlen(chunk_2);

    uint8_t digest_1[HACL_HASH_SHA3_256_DIGEST_LENGTH];
    uint8_t digest_2[HACL_HASH_SHA3_256_DIGEST_LENGTH];

    // Init
    Hacl_Streaming_Keccak_state* state =
      Hacl_Streaming_Keccak_malloc(Spec_Hash_Definitions_SHA3_256);
    Hacl_Streaming_Keccak_reset(state);

    // 1/2 Include `Hello, ` into the hash calculation and
    // obtain the intermediate hash of "Hello, ".
    uint32_t update_res =
      Hacl_Streaming_Keccak_update(state, (uint8_t*)chunk_1, chunk_1_size);
    ASSERT_EQ(0, update_res);
    // This is optional when no intermediate results are required.
    auto finish_res = Hacl_Streaming_Keccak_finish(state, digest_1);
    ASSERT_EQ(Hacl_Streaming_Keccak_Success, finish_res);

    // 2/2 Include `World!` into the hash calculation and
    // obtain the final hash of "Hello, World!".
    uint32_t update_res_2 =
      Hacl_Streaming_Keccak_update(state, (uint8_t*)chunk_2, chunk_2_size);
    ASSERT_EQ(0, update_res_2);
    auto finish_res_2 = Hacl_Streaming_Keccak_finish(state, digest_2);
    ASSERT_EQ(Hacl_Streaming_Keccak_Success, finish_res_2);

    // Cleanup
    Hacl_Streaming_Keccak_free(state);

    print_hex_ln(HACL_HASH_SHA3_256_DIGEST_LENGTH, digest_1);
    print_hex_ln(HACL_HASH_SHA3_256_DIGEST_LENGTH, digest_2);
    // ANCHOR_END(streaming)

    bytes expected_digest_1 = from_hex(
      "c942846170cfdf995f56688c396ad6b82cb09ed3aa37801a6ad1d23274cfb6ae");
    bytes expected_digest_2 = from_hex(
      "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef");

    EXPECT_EQ(strncmp((char*)digest_1,
                      (char*)expected_digest_1.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
    EXPECT_EQ(strncmp((char*)digest_2,
                      (char*)expected_digest_2.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
  }

  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // ANCHOR(example shake128)
    // This example uses SHAKE-128.

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    // SHAKE will generate as many bytes as requested.
    uint32_t digest_size = 42;
    uint8_t digest[42];

    Hacl_SHA3_shake128_hacl(
      message_size, (uint8_t*)message, digest_size, digest);
    // ANCHOR_END(example shake128)

    bytes expected_digest =
      from_hex("2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cb"
               "dd588f2c5dd4e465dfbaf");

    EXPECT_EQ(
      strncmp((char*)digest, (char*)expected_digest.data(), digest_size), 0);
  }
}

class Sha3KAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Sha3KAT, TryKAT)
{
  auto test_case = GetParam();

  {
    bytes digest(test_case.md.size(), 0);
    if (test_case.md.size() == 224 / 8) {
      Hacl_SHA3_sha3_224(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    } else if (test_case.md.size() == 256 / 8) {
      Hacl_SHA3_sha3_256(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    } else if (test_case.md.size() == 384 / 8) {
      Hacl_SHA3_sha3_384(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    } else if (test_case.md.size() == 512 / 8) {
      Hacl_SHA3_sha3_512(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    }

    EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest) << std::endl;
  }
}

class ShakeKAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(ShakeKAT, TryKAT)
{
  auto test_case = GetParam();

  {
    if (test_case.md.size() == 128 / 8) {
      bytes digest(test_case.md.size(), 128 / 8);

      Hacl_SHA3_shake128_hacl(test_case.msg.size(),
                              test_case.msg.data(),
                              digest.size(),
                              digest.data());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    } else if (test_case.md.size() == 256 / 8) {
      bytes digest(test_case.md.size(), 256 / 8);

      Hacl_SHA3_shake256_hacl(test_case.msg.size(),
                              test_case.msg.data(),
                              digest.size(),
                              digest.data());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
  Sha3_224ShortKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-224-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_224LongKAT,
  Sha3KAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-224-long.json"))));

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

INSTANTIATE_TEST_SUITE_P(
  Shake128ShortKAT,
  ShakeKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake128-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Shake128LongKAT,
  ShakeKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake128-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Shake256ShortKAT,
  ShakeKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake256-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Shake256LongKAT,
  ShakeKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake256-long.json"))));
