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
#include "Hacl_Hash_SHA2.h"
#include "Hacl_Spec.h"
#include "Hacl_Streaming_SHA2.h"
#include "config.h"
#include "evercrypt.h"
#include "util.h"

using json = nlohmann::json;
using namespace std;

// ANCHOR(example define)
// Note: HACL Packages will provide this (or a similar) define in a later
// version.
#define HACL_HASH_SHA2_256_DIGEST_LENGTH 32
// ANCHOR_END(example define)

class TestCase
{
public:
  bytes msg;
  bytes md;
};

ostream&
operator<<(ostream& os, const TestCase& test)
{
  os << "TestCase {" << endl
     << "\t.msg = " << bytes_to_hex(test.msg) << endl
     << "\t.md = " << bytes_to_hex(test.md) << endl
     << "}" << endl;
  return os;
}

vector<TestCase>
read_json(string test_file)
{
  // Read JSON test vector
  ifstream json_test_file(test_file);
  json test_vectors;
  json_test_file >> test_vectors;

  vector<TestCase> tests_out;

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
    // This example uses SHA2-256.
    //

    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    uint8_t digest[HACL_HASH_SHA2_256_DIGEST_LENGTH];

    Hacl_Hash_SHA2_hash_256(digest, (uint8_t*)message, message_size);
    // END OneShot

    bytes expected_digest = from_hex(
      "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");

    EXPECT_EQ(strncmp((char*)digest,
                      (char*)expected_digest.data(),
                      HACL_HASH_SHA2_256_DIGEST_LENGTH),
              0);
  }

  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // ANCHOR(example streaming)
    // This example shows how to hash the byte sequence "Hello, World!" in two
    // chunks. As a bonus, it also shows how to obtain intermediate results by
    // calling `digest` more than once.

    const char* chunk_1 = "Hello, ";
    const char* chunk_2 = "World!";
    uint32_t chunk_1_size = strlen(chunk_1);
    uint32_t chunk_2_size = strlen(chunk_2);

    uint8_t digest_1[HACL_HASH_SHA2_256_DIGEST_LENGTH];
    uint8_t digest_2[HACL_HASH_SHA2_256_DIGEST_LENGTH];

    // Init
    Hacl_Streaming_SHA2_state_sha2_256* state =
      Hacl_Streaming_SHA2_malloc_256();
    Hacl_Streaming_SHA2_reset_256(state);

    // 1/2 Include `Hello, ` into the hash calculation and
    // obtain the intermediate hash of "Hello, ".
    Hacl_Streaming_SHA2_update_256(state, (uint8_t*)chunk_1, chunk_1_size);
    // This is optional when no intermediate results are required.
    Hacl_Streaming_SHA2_digest_256(state, digest_1);

    // 2/2 Include `World!` into the hash calculation and
    // obtain the final hash of "Hello, World!".
    Hacl_Streaming_SHA2_update_256(state, (uint8_t*)chunk_2, chunk_2_size);
    Hacl_Streaming_SHA2_digest_256(state, digest_2);

    // Cleanup
    Hacl_Streaming_SHA2_free_256(state);

    print_hex_ln(HACL_HASH_SHA2_256_DIGEST_LENGTH, digest_1);
    print_hex_ln(HACL_HASH_SHA2_256_DIGEST_LENGTH, digest_2);
    // ANCHOR_END(example streaming)

    bytes expected_digest_1 = from_hex(
      "23429bd9ba98dd5140309bb9b0094b3aad642430fff6fb3ca61f008ce644f34a");
    bytes expected_digest_2 = from_hex(
      "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");

    EXPECT_EQ(strncmp((char*)digest_1,
                      (char*)expected_digest_1.data(),
                      HACL_HASH_SHA2_256_DIGEST_LENGTH),
              0);
    EXPECT_EQ(strncmp((char*)digest_2,
                      (char*)expected_digest_2.data(),
                      HACL_HASH_SHA2_256_DIGEST_LENGTH),
              0);
  }
}

class Sha2KAT : public ::testing::TestWithParam<tuple<TestCase, vector<size_t>>>
{};

TEST_P(Sha2KAT, TryKAT)
{
  TestCase test;
  vector<size_t> lengths;
  tie(test, lengths) = GetParam();

  bytes digest(test.md.size(), 0);
  if (test.md.size() == 224 / 8) {
    Hacl_Hash_SHA2_hash_224(digest.data(), test.msg.data(), test.msg.size());
  } else if (test.md.size() == 256 / 8) {
    Hacl_Hash_SHA2_hash_256(digest.data(), test.msg.data(), test.msg.size());
  } else if (test.md.size() == 384 / 8) {
    Hacl_Hash_SHA2_hash_384(digest.data(), test.msg.data(), test.msg.size());
  } else if (test.md.size() == 512 / 8) {
    Hacl_Hash_SHA2_hash_512(digest.data(), test.msg.data(), test.msg.size());
  }

  EXPECT_EQ(test.md, digest) << bytes_to_hex(test.md) << endl
                             << bytes_to_hex(digest) << endl;

  // Streaming
  {
    bytes digest(test.md.size(), 0);

    if (test.md.size() == 224 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_224* state =
        Hacl_Streaming_SHA2_malloc_224();
      Hacl_Streaming_SHA2_reset_224(state);

      // Update
      for (auto chunk : split_by_index_list(test.msg, lengths)) {
        Hacl_Streaming_SHA2_update_224(state, chunk.data(), chunk.size());
      }

      // Finish
      Hacl_Streaming_SHA2_digest_224(state, digest.data());
      Hacl_Streaming_SHA2_free_224(state);
    } else if (test.md.size() == 256 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_224* state =
        Hacl_Streaming_SHA2_malloc_256();
      Hacl_Streaming_SHA2_reset_256(state);

      // Update
      for (auto chunk : split_by_index_list(test.msg, lengths)) {
        Hacl_Streaming_SHA2_update_256(state, chunk.data(), chunk.size());
      }

      // Finish
      Hacl_Streaming_SHA2_digest_256(state, digest.data());
      Hacl_Streaming_SHA2_free_256(state);
    } else if (test.md.size() == 384 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_384* state =
        Hacl_Streaming_SHA2_malloc_384();
      Hacl_Streaming_SHA2_reset_384(state);

      // Update
      for (auto chunk : split_by_index_list(test.msg, lengths)) {
        Hacl_Streaming_SHA2_update_384(state, chunk.data(), chunk.size());
      }

      // Finish
      Hacl_Streaming_SHA2_digest_384(state, digest.data());
      Hacl_Streaming_SHA2_free_384(state);
    } else if (test.md.size() == 512 / 8) {
      // Init
      Hacl_Streaming_SHA2_state_sha2_512* state =
        Hacl_Streaming_SHA2_malloc_512();
      Hacl_Streaming_SHA2_reset_512(state);

      // Update
      for (auto chunk : split_by_index_list(test.msg, lengths)) {
        Hacl_Streaming_SHA2_update_512(state, chunk.data(), chunk.size());
      }

      // Finish
      Hacl_Streaming_SHA2_digest_512(state, digest.data());
      Hacl_Streaming_SHA2_free_512(state);
    }

    EXPECT_EQ(test.md, digest) << bytes_to_hex(test.md) << endl
                               << bytes_to_hex(digest) << endl;
  }
}

// ----- EverCrypt -------------------------------------------------------------

typedef EverCryptSuite<tuple<TestCase, vector<size_t>>> EverCryptSuiteTestCase;

TEST_P(EverCryptSuiteTestCase, HashTest)
{
  EverCryptConfig config;
  tuple<TestCase, vector<size_t>> test_tuple;
  tie(config, test_tuple) = this->GetParam();
  TestCase test;
  vector<size_t> lengths;
  tie(test, lengths) = test_tuple;

  {
    bytes got_digest(test.md.size(), 0);

    if (test.md.size() == 224 / 8) {
      EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_SHA2_224,
                                      got_digest.data(),
                                      test.msg.data(),
                                      test.msg.size());
    } else if (test.md.size() == 256 / 8) {
      EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_SHA2_256,
                                      got_digest.data(),
                                      test.msg.data(),
                                      test.msg.size());
    } else if (test.md.size() == 384 / 8) {
      EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_SHA2_384,
                                      got_digest.data(),
                                      test.msg.data(),
                                      test.msg.size());
    } else if (test.md.size() == 512 / 8) {
      EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_SHA2_512,
                                      got_digest.data(),
                                      test.msg.data(),
                                      test.msg.size());
    } else {
      FAIL();
    }

    EXPECT_EQ(test.md, got_digest);
  }

  // Streaming
  {
    bytes got_digest(test.md.size(), 0);

    EverCrypt_Hash_Incremental_state_t* state;
    if (test.md.size() == 224 / 8) {
      state =
        EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_SHA2_224);
    } else if (test.md.size() == 256 / 8) {
      state =
        EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_SHA2_256);
    } else if (test.md.size() == 384 / 8) {
      state =
        EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_SHA2_384);
    } else if (test.md.size() == 512 / 8) {
      state =
        EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_SHA2_512);
    } else {
      FAIL();
    }

    EverCrypt_Hash_Incremental_reset(state);

    for (auto chunk : split_by_index_list(test.msg, lengths)) {
      EverCrypt_Hash_Incremental_update(state, chunk.data(), chunk.size());
    }

    EverCrypt_Hash_Incremental_digest(state, got_digest.data());
    EverCrypt_Hash_Incremental_free(state);

    EXPECT_EQ(test.md, got_digest);
  }
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  CryspenSha224,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_224.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  CryspenSha256,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_256.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  CryspenSha384,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_384.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  CryspenSha512,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_512.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha224ShortKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha224-short.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha224LongKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha224-long.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha256ShortKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha256-short.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha256LongKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha256-long.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha384ShortKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha384-short.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha384LongKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha384-short.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha512ShortKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha512-short.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha512LongKAT,
  Sha2KAT,
  ::testing::Combine(::testing::ValuesIn(read_json("sha512-short.json")),
                     ::testing::ValuesIn(make_lengths())));

// ----- EverCrypt -------------------------------------------------------------

// SHA2-256 can use "Intel SHA extensions".
// We test w/ and w/o SHAEXT enabled.
vector<EverCryptConfig>
generate_sha2_configs()
{
  vector<EverCryptConfig> configs;

  // SHAEXT "enabled" (when supported).
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

  // SHAEXT disabled.
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
    .disable_shaext = true,
    .disable_sse = false,
  });

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  Sha2224,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_224.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha2256,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_256.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha2384,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_384.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha2512,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha2_512.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha224ShortKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha224-short.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha224LongKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha224-long.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha256ShortKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha256-short.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha256LongKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha256-long.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha384ShortKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha384-short.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha384LongKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha384-long.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha512ShortKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha512-short.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha512LongKAT,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha2_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha512-long.json")),
                       ::testing::ValuesIn(make_lengths()))));
