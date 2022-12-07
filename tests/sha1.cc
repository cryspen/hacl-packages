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
#include "Hacl_Spec.h"
#include "Hacl_Streaming_SHA1.h"
#include "config.h"
#include "evercrypt.h"
#include "util.h"

using json = nlohmann::json;
using namespace std;

// ANCHOR(example define)
// Note: HACL Packages will provide this (or a similar) define in a later
// version.
#define HACL_HASH_SHA1_DIGEST_LENGTH 20
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
    const char* message = "Hello, World!";
    uint32_t message_size = strlen(message);

    // 160 Bit / 8 = 20 Byte
    uint8_t digest[160 / 8];

    Hacl_Hash_SHA1_legacy_hash((uint8_t*)message, message_size, digest);
    // END OneShot

    bytes expected_digest =
      from_hex("0a0a9f2a6772942557ab5355d76af442f8f65e01");

    EXPECT_EQ(strncmp((char*)digest, (char*)expected_digest.data(), 20), 0);
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

    uint8_t digest_1[HACL_HASH_SHA1_DIGEST_LENGTH];
    uint8_t digest_2[HACL_HASH_SHA1_DIGEST_LENGTH];

    // Init
    Hacl_Streaming_SHA1_state_sha1* state =
      Hacl_Streaming_SHA1_legacy_create_in_sha1();
    Hacl_Streaming_SHA1_legacy_init_sha1(state);

    // 1/2 Include `Hello, ` into the hash calculation and
    // obtain the intermediate hash of "Hello, ".
    Hacl_Streaming_SHA1_legacy_update_sha1(
      state, (uint8_t*)chunk_1, chunk_1_size);
    // This is optional when no intermediate results are required.
    Hacl_Streaming_SHA1_legacy_finish_sha1(state, digest_1);

    // 2/2 Include `World!` into the hash calculation and
    // obtain the final hash of "Hello, World!".
    Hacl_Streaming_SHA1_legacy_update_sha1(
      state, (uint8_t*)chunk_2, chunk_2_size);
    Hacl_Streaming_SHA1_legacy_finish_sha1(state, digest_2);

    // Cleanup
    Hacl_Streaming_SHA1_legacy_free_sha1(state);

    print_hex_ln(HACL_HASH_SHA1_DIGEST_LENGTH, digest_1);
    print_hex_ln(HACL_HASH_SHA1_DIGEST_LENGTH, digest_2);
    // ANCHOR_END(streaming)

    bytes expected_digest_1 =
      from_hex("f52ab57fa51dfa714505294444463ae5a009ae34");
    bytes expected_digest_2 =
      from_hex("0a0a9f2a6772942557ab5355d76af442f8f65e01");

    EXPECT_EQ(strncmp((char*)digest_1,
                      (char*)expected_digest_1.data(),
                      HACL_HASH_SHA1_DIGEST_LENGTH),
              0);
    EXPECT_EQ(strncmp((char*)digest_2,
                      (char*)expected_digest_2.data(),
                      HACL_HASH_SHA1_DIGEST_LENGTH),
              0);
  }
}

class Sha1 : public ::testing::TestWithParam<tuple<TestCase, vector<size_t>>>
{};

TEST_P(Sha1, KAT)
{
  TestCase test;
  vector<size_t> lengths;
  tie(test, lengths) = GetParam();

  bytes digest(test.md.size());

  // Init
  Hacl_Streaming_SHA2_state_sha2_224* state =
    Hacl_Streaming_SHA1_legacy_create_in_sha1();
  Hacl_Streaming_SHA1_legacy_init_sha1(state);

  // Update
  for (auto chunk : split_by_index_list(test.msg, lengths)) {
    Hacl_Streaming_SHA1_legacy_update_sha1(state, chunk.data(), chunk.size());
  }

  // Finish
  Hacl_Streaming_SHA1_legacy_finish_sha1(state, digest.data());
  Hacl_Streaming_SHA1_legacy_free_sha1(state);

  EXPECT_EQ(test.md, digest) << bytes_to_hex(test.md) << endl
                             << bytes_to_hex(digest) << endl;
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
    bytes got_digest(
      Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_SHA1));

    EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA1,
                        got_digest.data(),
                        test.msg.data(),
                        test.msg.size());
    ASSERT_EQ(test.md, got_digest);
  }

  {
    bytes got_digest(
      Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_SHA1));

    // Use a typedef?
    Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____* state =
      EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA1);
    EverCrypt_Hash_Incremental_init(state);

    for (auto chunk : split_by_index_list(test.msg, lengths)) {
      EverCrypt_Hash_Incremental_update(state, chunk.data(), chunk.size());
    }

    EverCrypt_Hash_Incremental_finish(state, got_digest.data());
    EverCrypt_Hash_Incremental_free(state);

    ASSERT_EQ(test.md, got_digest);
  }
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  Sha1Cryspen,
  Sha1,
  ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha1.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPShort,
  Sha1,
  ::testing::Combine(::testing::ValuesIn(read_json("sha1-short.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPLong,
  Sha1,
  ::testing::Combine(::testing::ValuesIn(read_json("sha1-long.json")),
                     ::testing::ValuesIn(make_lengths())));

// ----- EverCrypt -------------------------------------------------------------

// SHA1 does not use additional hardware features.
// Nothing to disable here.
vector<EverCryptConfig>
generate_sha1_configs()
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
  Sha1Cryspen,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha1_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("cryspen_sha1.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPShort,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha1_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha1-short.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPLong,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_sha1_configs()),
    ::testing::Combine(::testing::ValuesIn(read_json("sha1-long.json")),
                       ::testing::ValuesIn(make_lengths()))));
