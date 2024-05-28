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
#include "Hacl_Hash_SHA3_Scalar.h"
#include "hacl-cpu-features.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_SHA3_Simd256.h"
#endif

#include "config.h"
#include "util.h"

#include "libcrux_sha3.h"

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

    Hacl_Hash_SHA3_sha3_256(digest, (uint8_t*)message, message_size);
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
    // calling `digest` more than once.

    const char* chunk_1 = "Hello, ";
    const char* chunk_2 = "World!";
    uint32_t chunk_1_size = strlen(chunk_1);
    uint32_t chunk_2_size = strlen(chunk_2);

    uint8_t digest_1[HACL_HASH_SHA3_256_DIGEST_LENGTH];
    uint8_t digest_2[HACL_HASH_SHA3_256_DIGEST_LENGTH];

    // Init
    Hacl_Hash_SHA3_state_t* state =
      Hacl_Hash_SHA3_malloc(Spec_Hash_Definitions_SHA3_256);

    // 1/2 Include `Hello, ` into the hash calculation and
    // obtain the intermediate hash of "Hello, ".
    uint32_t update_res =
      Hacl_Hash_SHA3_update(state, (uint8_t*)chunk_1, chunk_1_size);
    ASSERT_EQ(0, update_res);
    // This is optional when no intermediate results are required.
    auto finish_res = Hacl_Hash_SHA3_digest(state, digest_1);
    ASSERT_EQ(Hacl_Streaming_Types_Success, finish_res);

    // 2/2 Include `World!` into the hash calculation and
    // obtain the final hash of "Hello, World!".
    uint32_t update_res_2 =
      Hacl_Hash_SHA3_update(state, (uint8_t*)chunk_2, chunk_2_size);
    ASSERT_EQ(0, update_res_2);
    auto finish_res_2 = Hacl_Hash_SHA3_digest(state, digest_2);
    ASSERT_EQ(Hacl_Streaming_Types_Success, finish_res_2);

    // Cleanup
    Hacl_Hash_SHA3_free(state);

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

    Hacl_Hash_SHA3_shake128_hacl(
      message_size, (uint8_t*)message, digest_size, digest);
    // ANCHOR_END(example shake128)

    bytes expected_digest =
      from_hex("2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cb"
               "dd588f2c5dd4e465dfbaf");

    EXPECT_EQ(
      strncmp((char*)digest, (char*)expected_digest.data(), digest_size), 0);
  }

  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // ANCHOR(example scalar_sha3_256)
    // This example uses Scalar SHA3-256.

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    uint8_t digest[HACL_HASH_SHA3_256_DIGEST_LENGTH];

    Hacl_Hash_SHA3_Scalar_sha3_256(digest, (uint8_t*)message, message_size);
    // ANCHOR_END(example scalar_sha3_256)

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
    // ANCHOR(example scalar_shake128)
    // This example uses Scalar SHAKE-128.

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    // SHAKE will generate as many bytes as requested.
    uint32_t digest_size = 42;
    uint8_t digest[42];

    Hacl_Hash_SHA3_Scalar_shake128(
      digest, digest_size, (uint8_t*)message, message_size);
    // ANCHOR_END(example scalar_shake128)

    bytes expected_digest =
      from_hex("2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cb"
               "dd588f2c5dd4e465dfbaf");

    EXPECT_EQ(
      strncmp((char*)digest, (char*)expected_digest.data(), digest_size), 0);
  }

  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // ANCHOR(example libcrux_sha3_sha256)
    // This example uses libcrux SHA3-256.

    // TESTING HELLO-WORLD for LIBCRUX


    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    uint8_t digest[HACL_HASH_SHA3_256_DIGEST_LENGTH];
    Eurydice_slice input;
    input.ptr = (void*) message;
    input.len = message_size;

    libcrux_sha3_sha256(input,digest);
    // ANCHOR_END(example libcrux_sha3_sha256)

    bytes expected_digest = from_hex(
      "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef");

    EXPECT_EQ(strncmp((char*)digest,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
  }


#ifdef HACL_CAN_COMPILE_VEC128
  hacl_init_cpu_features();
  if (hacl_vec128_support()) {
  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // ANCHOR(example libcrux_sha3_neon_sha256)
    // This example uses libcrux Neon SHA3-256.

    //  printf(" TESTING HELLO-WORLD for LIBCRUX Neon \n");

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    uint8_t digest[HACL_HASH_SHA3_256_DIGEST_LENGTH];

    Eurydice_slice input;
    input.ptr = (void*) message;
    input.len = message_size;

    Eurydice_slice output;
    output.ptr = (void*) digest;
    output.len = 32;

    libcrux_sha3_neon_sha256(output,input);
    // ANCHOR_END(example libcrux_sha3_neon_sha256)

    bytes expected_digest = from_hex(
      "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef");

    EXPECT_EQ(strncmp((char*)digest,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA3_256_DIGEST_LENGTH),
              0);
  }
}
#endif

  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // ANCHOR(example scalar_shake128)
    // This example uses Scalar SHAKE-128.

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    // SHAKE will generate as many bytes as requested.
    uint32_t digest_size = 42;
    uint8_t digest[42];

    Hacl_Hash_SHA3_Scalar_shake128(
      digest, digest_size, (uint8_t*)message, message_size);
    // ANCHOR_END(example scalar_shake128)

    bytes expected_digest =
      from_hex("2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cb"
               "dd588f2c5dd4e465dfbaf");

    EXPECT_EQ(
      strncmp((char*)digest, (char*)expected_digest.data(), digest_size), 0);
  }

#ifdef HACL_CAN_COMPILE_VEC256
  hacl_init_cpu_features();
  if (hacl_vec256_support()) {
    // Documentation.
    // Lines after START and before END are used in documentation.
    {
      // ANCHOR(example vec256_sha3_256)
      // This example uses Vec256 SHA3-256.

      const char* message = "Hello, World!";
      uint32_t message_size = strlen(message);

      uint8_t digest0[HACL_HASH_SHA3_256_DIGEST_LENGTH];
      uint8_t digest1[HACL_HASH_SHA3_256_DIGEST_LENGTH];
      uint8_t digest2[HACL_HASH_SHA3_256_DIGEST_LENGTH];
      uint8_t digest3[HACL_HASH_SHA3_256_DIGEST_LENGTH];

      Hacl_Hash_SHA3_Simd256_sha3_256(digest0,
                                       digest1,
                                       digest2,
                                       digest3,
                                       (uint8_t*)message,
                                       (uint8_t*)message,
                                       (uint8_t*)message,
                                       (uint8_t*)message,
                                       message_size);
      // ANCHOR_END(example vec256_sha3_256)

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
    {
      // ANCHOR(example vec256_shake128)
      // This example uses Vec256 SHAKE-128.

      const char* message0 = "Hello, World1!";
      const char* message1 = "Hello, World2!";
      const char* message2 = "Hello, World3!";
      const char* message3 = "Hello, World4!";
      uint32_t message_size = 14;

      // SHAKE will generate as many bytes as requested.
      uint32_t digest_size = 42;
      uint8_t digest0[42];
      uint8_t digest1[42];
      uint8_t digest2[42];
      uint8_t digest3[42];

      Hacl_Hash_SHA3_Simd256_shake128(digest0,
                                       digest1,
                                       digest2,
                                       digest3,
                                       digest_size,
                                       (uint8_t*)message0,
                                       (uint8_t*)message1,
                                       (uint8_t*)message2,
                                       (uint8_t*)message3,
                                       message_size);
      // ANCHOR_END(example vec256_shake128)

      bytes expected_digest0 = from_hex(
        "1b82c3db6cb958a09a7ea3dd82b67a9c994422c39616ec373afafcf2fca8bca"
        "808881328f9ca03eb119a");
      bytes expected_digest1 = from_hex(
        "3c8f0ab13109dff341fbe0e7511bd8bdfa8d13335b36acdb391170017c6d45f"
        "460964cab081699f6e45d");
      bytes expected_digest2 = from_hex(
        "86ee9003051369f1d5461b00263e01cac1c65defaf722e6ed648fba99743a14"
        "9b39abc52d6fc746f5014");
      bytes expected_digest3 = from_hex(
        "0b9efd21050944cb5ba5df0cc35a176100201e3fd7c4f2b9f70a9dfd4a7228b"
        "5d676451df013d3e22ac9");

      EXPECT_EQ(
        strncmp((char*)digest0, (char*)expected_digest0.data(), digest_size),
        0);
      EXPECT_EQ(
        strncmp((char*)digest1, (char*)expected_digest1.data(), digest_size),
        0);
      EXPECT_EQ(
        strncmp((char*)digest2, (char*)expected_digest2.data(), digest_size),
        0);
      EXPECT_EQ(
        strncmp((char*)digest3, (char*)expected_digest3.data(), digest_size),
        0);
    }
  }
#endif
}

class Sha3KAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Sha3KAT, TryKAT)
{
  auto test_case = GetParam();

  {
    bytes digest(test_case.md.size(), 0);
    if (test_case.md.size() == 224 / 8) {
      Hacl_Hash_SHA3_sha3_224(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    } else if (test_case.md.size() == 256 / 8) {
      Hacl_Hash_SHA3_sha3_256(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    } else if (test_case.md.size() == 384 / 8) {
      Hacl_Hash_SHA3_sha3_384(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    } else if (test_case.md.size() == 512 / 8) {
      Hacl_Hash_SHA3_sha3_512(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    }

    EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest) << std::endl;
  }

  {
    bytes digest(test_case.md.size(), 0);
    if (test_case.md.size() == 224 / 8) {
      Hacl_Hash_SHA3_Scalar_sha3_224(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    } else if (test_case.md.size() == 256 / 8) {
      Hacl_Hash_SHA3_Scalar_sha3_256(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    } else if (test_case.md.size() == 384 / 8) {
      Hacl_Hash_SHA3_Scalar_sha3_384(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    } else if (test_case.md.size() == 512 / 8) {
      Hacl_Hash_SHA3_Scalar_sha3_512(
        digest.data(), test_case.msg.data(), test_case.msg.size());
    }

    EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest) << std::endl;
  }

  {
    // TESTING KATS for LIBCRUX
    bytes digest(test_case.md.size(), 0);
    Eurydice_slice input;
    input.ptr = test_case.msg.data();
    input.len = test_case.msg.size();
    if (test_case.md.size() == 224 / 8) {
      libcrux_sha3_sha224(input,digest.data());
    } else if (test_case.md.size() == 256 / 8) {
      libcrux_sha3_sha256(input,digest.data());
    } else if (test_case.md.size() == 384 / 8) {
      libcrux_sha3_sha384(input,digest.data());
    } else if (test_case.md.size() == 512 / 8) {
      libcrux_sha3_sha512(input,digest.data());
    }

    EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest) << std::endl;
  }

#ifdef HACL_CAN_COMPILE_VEC128
  hacl_init_cpu_features();
  if (hacl_vec128_support()) {
  {
    // TESTING KATS for LIBCRUX
    bytes digest(test_case.md.size(), 0);
    Eurydice_slice input;
    input.ptr = test_case.msg.data();
    input.len = test_case.msg.size();
    Eurydice_slice output;
    output.ptr = (void*) digest.data();
    output.len = test_case.md.size();

    if (test_case.md.size() == 224 / 8) {
      libcrux_sha3_neon_sha224(output,input);
    } else if (test_case.md.size() == 256 / 8) {
      libcrux_sha3_neon_sha256(output,input);
    } else if (test_case.md.size() == 384 / 8) {
      libcrux_sha3_neon_sha384(output,input);
    } else if (test_case.md.size() == 512 / 8) {
      libcrux_sha3_neon_sha512(output,input);
    }

    EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                    << bytes_to_hex(digest) << std::endl;
  }
  }
#endif

#ifdef HACL_CAN_COMPILE_VEC256
  hacl_init_cpu_features();
  if (hacl_vec256_support()) {
    bytes digest0(test_case.md.size(), 0);
    bytes digest1(test_case.md.size(), 0);
    bytes digest2(test_case.md.size(), 0);
    bytes digest3(test_case.md.size(), 0);
    if (test_case.md.size() == 224 / 8) {
      Hacl_Hash_SHA3_Simd256_sha3_224(digest0.data(),
                                       digest1.data(),
                                       digest2.data(),
                                       digest3.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.size());
    } else if (test_case.md.size() == 256 / 8) {
      Hacl_Hash_SHA3_Simd256_sha3_256(digest0.data(),
                                       digest1.data(),
                                       digest2.data(),
                                       digest3.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.size());
    } else if (test_case.md.size() == 384 / 8) {
      Hacl_Hash_SHA3_Simd256_sha3_384(digest0.data(),
                                       digest1.data(),
                                       digest2.data(),
                                       digest3.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.size());
    } else if (test_case.md.size() == 512 / 8) {
      Hacl_Hash_SHA3_Simd256_sha3_512(digest0.data(),
                                       digest1.data(),
                                       digest2.data(),
                                       digest3.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.size());
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

class ShakeKAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(ShakeKAT, TryKAT)
{
  auto test_case = GetParam();

  {
    if (test_case.md.size() == 128 / 8) {
      bytes digest(test_case.md.size(), 128 / 8);

      Hacl_Hash_SHA3_shake128_hacl(test_case.msg.size(),
                                   test_case.msg.data(),
                                   digest.size(),
                                   digest.data());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    } else if (test_case.md.size() == 256 / 8) {
      bytes digest(test_case.md.size(), 256 / 8);

      Hacl_Hash_SHA3_shake256_hacl(test_case.msg.size(),
                                   test_case.msg.data(),
                                   digest.size(),
                                   digest.data());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    }
  }

  {
    if (test_case.md.size() == 128 / 8) {
      bytes digest(test_case.md.size(), 128 / 8);

      Hacl_Hash_SHA3_Scalar_shake128(digest.data(),
                                     digest.size(),
                                     test_case.msg.data(),
                                     test_case.msg.size());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    } else if (test_case.md.size() == 256 / 8) {
      bytes digest(test_case.md.size(), 256 / 8);

      Hacl_Hash_SHA3_Scalar_shake256(digest.data(),
                                     digest.size(),
                                     test_case.msg.data(),
                                     test_case.msg.size());

      EXPECT_EQ(test_case.md, digest) << bytes_to_hex(test_case.md) << std::endl
                                      << bytes_to_hex(digest) << std::endl;
    }
  }

#ifdef HACL_CAN_COMPILE_VEC256
  hacl_init_cpu_features();
  if (hacl_vec256_support()) {
    if (test_case.md.size() == 128 / 8) {
      bytes digest0(test_case.md.size(), 128 / 8);
      bytes digest1(test_case.md.size(), 128 / 8);
      bytes digest2(test_case.md.size(), 128 / 8);
      bytes digest3(test_case.md.size(), 128 / 8);

      Hacl_Hash_SHA3_Simd256_shake128(digest0.data(),
                                       digest1.data(),
                                       digest2.data(),
                                       digest3.data(),
                                       digest0.size(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.size());

      EXPECT_EQ(test_case.md, digest0)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest0) << std::endl;
      EXPECT_EQ(test_case.md, digest1)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest1) << std::endl;
      EXPECT_EQ(test_case.md, digest2)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest2) << std::endl;
      EXPECT_EQ(test_case.md, digest3)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest3) << std::endl;
    } else if (test_case.md.size() == 256 / 8) {
      bytes digest0(test_case.md.size(), 256 / 8);
      bytes digest1(test_case.md.size(), 256 / 8);
      bytes digest2(test_case.md.size(), 256 / 8);
      bytes digest3(test_case.md.size(), 256 / 8);

      Hacl_Hash_SHA3_Simd256_shake256(digest0.data(),
                                       digest1.data(),
                                       digest2.data(),
                                       digest3.data(),
                                       digest0.size(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.data(),
                                       test_case.msg.size());

      EXPECT_EQ(test_case.md, digest0)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest0) << std::endl;
      EXPECT_EQ(test_case.md, digest1)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest1) << std::endl;
      EXPECT_EQ(test_case.md, digest2)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest2) << std::endl;
      EXPECT_EQ(test_case.md, digest3)
        << bytes_to_hex(test_case.md) << std::endl
        << bytes_to_hex(digest3) << std::endl;
    }
  }
#endif
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
