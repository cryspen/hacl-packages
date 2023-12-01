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

#include "Hacl_SHA3_Scalar.h"
#include "hacl-cpu-features.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_SHA3_Vec256.h"
#endif

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
    // This example uses Scalar SHA3-256.
    //

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    uint8_t digest[HACL_HASH_SHA3_256_DIGEST_LENGTH];

    Hacl_SHA3_Scalar_sha3_256(message_size, (uint8_t*)message, digest);
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
    // ANCHOR(example shake128)
    // This example uses Scalar SHAKE-128.

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    // SHAKE will generate as many bytes as requested.
    uint32_t digest_size = 42;
    uint8_t digest[42];

    Hacl_SHA3_Scalar_shake128_hacl(
      message_size, (uint8_t*)message, digest_size, digest);
    // ANCHOR_END(example shake128)

    bytes expected_digest =
      from_hex("2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cb"
               "dd588f2c5dd4e465dfbaf");

    EXPECT_EQ(
      strncmp((char*)digest, (char*)expected_digest.data(), digest_size), 0);
  }

#ifdef HACL_CAN_COMPILE_VEC256
  // Documentation.
  // Lines after START and before END are used in documentation.
  if (hacl_vec256_support())
  {
    // START OneShot
    // This example uses Vec256 SHA3-256.
    //

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    uint8_t digest0[HACL_HASH_SHA3_256_DIGEST_LENGTH];
    uint8_t digest1[HACL_HASH_SHA3_256_DIGEST_LENGTH];
    uint8_t digest2[HACL_HASH_SHA3_256_DIGEST_LENGTH];
    uint8_t digest3[HACL_HASH_SHA3_256_DIGEST_LENGTH];

    Hacl_SHA3_Vec256_sha3_256_vec256(message_size,
      (uint8_t*)message, (uint8_t*)message, (uint8_t*)message, (uint8_t*)message,
      digest0, digest1, digest2, digest3);
    // END OneShot

    bytes expected_digest = from_hex(
      "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef");

    EXPECT_EQ(strncmp((char*)digest0,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
    EXPECT_EQ(strncmp((char*)digest1,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
    EXPECT_EQ(strncmp((char*)digest2,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
    EXPECT_EQ(strncmp((char*)digest3,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
  }

  // Documentation.
  // Lines after START and before END are used in documentation.
  if (hacl_vec256_support())
  {
    // ANCHOR(example shake128)
    // This example uses Vec256 SHAKE-128.

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    // SHAKE will generate as many bytes as requested.
    uint32_t digest_size = 42;
    uint8_t digest0[42];
    uint8_t digest1[42];
    uint8_t digest2[42];
    uint8_t digest3[42];

    Hacl_SHA3_Vec256_shake128_vec256(message_size,
       (uint8_t*)message, (uint8_t*)message, (uint8_t*)message, (uint8_t*)message, 
       digest_size, digest0, digest1, digest2, digest3);
    // ANCHOR_END(example shake128)

    bytes expected_digest =
      from_hex("2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cb"
               "dd588f2c5dd4e465dfbaf");

    EXPECT_EQ(
      strncmp((char*)digest0, (char*)expected_digest.data(), digest_size), 0);
    EXPECT_EQ(
      strncmp((char*)digest1, (char*)expected_digest.data(), digest_size), 0);
    EXPECT_EQ(
      strncmp((char*)digest2, (char*)expected_digest.data(), digest_size), 0);
    EXPECT_EQ(
      strncmp((char*)digest3, (char*)expected_digest.data(), digest_size), 0);
  }
#endif
}

class Sha3MBKAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Sha3MBKAT, TryKAT)
{
  auto test_case = GetParam();

  {
    bytes digest(test_case.md.size(), 0);
    if (test_case.md.size() == 224 / 8) {
      Hacl_SHA3_Scalar_sha3_224(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    } else if (test_case.md.size() == 256 / 8) {
      Hacl_SHA3_Scalar_sha3_256(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    } else if (test_case.md.size() == 384 / 8) {
      Hacl_SHA3_Scalar_sha3_384(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    } else if (test_case.md.size() == 512 / 8) {
      Hacl_SHA3_Scalar_sha3_512(
        test_case.msg.size(), test_case.msg.data(), digest.data());
    }

    EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest) << std::endl;
  }

#ifdef HACL_CAN_COMPILE_VEC256
  if (hacl_vec256_support())
  {
    bytes digest0(test_case.md.size(), 0);
    bytes digest1(test_case.md.size(), 0);
    bytes digest2(test_case.md.size(), 0);
    bytes digest3(test_case.md.size(), 0);
    if (test_case.md.size() == 224 / 8) {
      Hacl_SHA3_Vec256_sha3_224_vec256(
        test_case.msg.size(),
        test_case.msg.data(), test_case.msg.data(), test_case.msg.data(), test_case.msg.data(),
        digest0.data(), digest1.data(), digest2.data(), digest3.data());
    } else if (test_case.md.size() == 256 / 8) {
      Hacl_SHA3_Vec256_sha3_256_vec256(
        test_case.msg.size(),
        test_case.msg.data(), test_case.msg.data(), test_case.msg.data(), test_case.msg.data(),
        digest0.data(), digest1.data(), digest2.data(), digest3.data());
    } else if (test_case.md.size() == 384 / 8) {
      Hacl_SHA3_Vec256_sha3_384_vec256(
        test_case.msg.size(),
        test_case.msg.data(), test_case.msg.data(), test_case.msg.data(), test_case.msg.data(),
        digest0.data(), digest1.data(), digest2.data(), digest3.data());
    } else if (test_case.md.size() == 512 / 8) {
      Hacl_SHA3_Vec256_sha3_512_vec256(
        test_case.msg.size(),
        test_case.msg.data(), test_case.msg.data(), test_case.msg.data(), test_case.msg.data(),
        digest0.data(), digest1.data(), digest2.data(), digest3.data());
    }

    EXPECT_EQ(test_case.md, digest0) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest0) << std::endl;
    EXPECT_EQ(test_case.md, digest1) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest1) << std::endl;
    EXPECT_EQ(test_case.md, digest2) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest2) << std::endl;
    EXPECT_EQ(test_case.md, digest3) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest3) << std::endl;
  }
#endif
}

class ShakeMBKAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(ShakeMBKAT, TryKAT)
{
  auto test_case = GetParam();

  {
    if (test_case.md.size() == 128 / 8) {
      bytes digest(test_case.md.size(), 128 / 8);

      Hacl_SHA3_Scalar_shake128_hacl(test_case.msg.size(),
                                     test_case.msg.data(),
                                     digest.size(),
                                     digest.data());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    } else if (test_case.md.size() == 256 / 8) {
      bytes digest(test_case.md.size(), 256 / 8);

      Hacl_SHA3_Scalar_shake256_hacl(test_case.msg.size(),
                                     test_case.msg.data(),
                                     digest.size(),
                                     digest.data());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    }
  }

#ifdef HACL_CAN_COMPILE_VEC256
  if (hacl_vec256_support())
  {
    if (test_case.md.size() == 128 / 8) {
      bytes digest0(test_case.md.size(), 128 / 8);
      bytes digest1(test_case.md.size(), 128 / 8);
      bytes digest2(test_case.md.size(), 128 / 8);
      bytes digest3(test_case.md.size(), 128 / 8);

      Hacl_SHA3_Vec256_shake128_vec256(test_case.msg.size(),
                                     test_case.msg.data(),
                                     test_case.msg.data(),
                                     test_case.msg.data(),
                                     test_case.msg.data(),
                                     digest0.size(),
                                     digest0.data(),
                                     digest1.data(),
                                     digest2.data(),
                                     digest3.data());

      EXPECT_EQ(test_case.md, digest0) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest0) << std::endl;
      EXPECT_EQ(test_case.md, digest1) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest1) << std::endl;
      EXPECT_EQ(test_case.md, digest2) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest2) << std::endl;
      EXPECT_EQ(test_case.md, digest3) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest3) << std::endl;
    } else if (test_case.md.size() == 256 / 8) {
      bytes digest0(test_case.md.size(), 256 / 8);
      bytes digest1(test_case.md.size(), 256 / 8);
      bytes digest2(test_case.md.size(), 256 / 8);
      bytes digest3(test_case.md.size(), 256 / 8);

      Hacl_SHA3_Vec256_shake256_vec256(test_case.msg.size(),
                                     test_case.msg.data(),
                                     test_case.msg.data(),
                                     test_case.msg.data(),
                                     test_case.msg.data(),
                                     digest0.size(),
                                     digest0.data(),
                                     digest1.data(),
                                     digest2.data(),
                                     digest3.data());

      EXPECT_EQ(test_case.md, digest0) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest0) << std::endl;
      EXPECT_EQ(test_case.md, digest1) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest1) << std::endl;
      EXPECT_EQ(test_case.md, digest2) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest2) << std::endl;
      EXPECT_EQ(test_case.md, digest3) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest3) << std::endl;
    }
  }
#endif
}

INSTANTIATE_TEST_SUITE_P(
  Sha3_224ShortKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-224-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_224LongKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-224-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_256ShortKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-256-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_256LongKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-256-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_384ShortKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-384-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_384LongKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-384-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_512ShortKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-512-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha3_512LongKAT,
  Sha3MBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("sha3-512-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Shake128ShortKAT,
  ShakeMBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake128-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Shake128LongKAT,
  ShakeMBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake128-long.json"))));

INSTANTIATE_TEST_SUITE_P(
  Shake256ShortKAT,
  ShakeMBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake256-short.json"))));

INSTANTIATE_TEST_SUITE_P(
  Shake256LongKAT,
  ShakeMBKAT,
  ::testing::ValuesIn(read_json(const_cast<char*>("shake256-long.json"))));
