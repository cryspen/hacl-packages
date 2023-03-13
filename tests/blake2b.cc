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
// ANCHOR(example header)
#include "Hacl_Hash_Blake2b_32.h"
// ANCHOR_END(example header)
#include "config.h"
#include "evercrypt.h"
#include "hacl-cpu-features.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_Simd256.h"
#endif

#define VALE                                                                   \
  TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64 ||                         \
    TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X86

#if VALE
// Only include this for checking CPU flags.
#include "Vale.h"
#endif

// ANCHOR(example define)
// Note: HACL Packages will provide this (or a similar) define in a later
// version.
#define HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX 64
// ANCHOR_END(example define)

using json = nlohmann::json;
using namespace std;

// -----------------------------------------------------------------------------

TEST(ApiTestSuite, ApiTest)
{
  {
    // ANCHOR(example)
    // Reserve memory for a 64 byte digest, i.e.,
    // for a BLAKE2b run with full 512-bit output.
    uint8_t output[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // The message we want to hash.
    const char* message = "Hello, HACL Packages!";
    uint32_t message_len = strlen(message);

    // BLAKE2b can be used as an HMAC, i.e., with a key.
    // We don't want to use a key here and thus provide a zero-sized key.
    uint32_t key_len = 0;
    uint8_t* key = 0;

    Hacl_Hash_Blake2b_32_hash_with_key(output,
                                       HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX,
                                       (uint8_t*)message,
                                       message_len,
                                       key,
                                       key_len);

    print_hex_ln(HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX, output);
    // ANCHOR_END(example)

    bytes expected_digest = from_hex(
      "f99574aa3ba6cf78ad48e1f22a77e7aef1d7433c1cb3d424d14ae5ec51af8c6dc8bf41cb"
      "0a10383274f256df0f7d0f145a043b7a77f4c17e47e535f72a4e1f43");

    EXPECT_EQ(strncmp((char*)output,
                      (char*)expected_digest.data(),
                      HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX),
              0);
  }

  {
    // ANCHOR(example streaming)
    // This example shows how to hash the byte sequence "Hello, World!" in two
    // chunks. As a bonus, it also shows how to obtain intermediate results by
    // calling `finish` more than once.

    const char* chunk_1 = "Hello, ";
    const char* chunk_2 = "World!";
    uint32_t chunk_1_size = strlen(chunk_1);
    uint32_t chunk_2_size = strlen(chunk_2);

    uint8_t digest_1[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];
    uint8_t digest_2[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Hash_Blake2b_32_state_t* state = Hacl_Hash_Blake2b_32_malloc();
    Hacl_Hash_Blake2b_32_reset(state);

    // 1/2 Include `Hello, ` into the hash calculation and
    // obtain the intermediate hash of "Hello, ".
    Hacl_Hash_Blake2b_32_update(state, (uint8_t*)chunk_1, chunk_1_size);
    // This is optional when no intermediate results are required.
    Hacl_Hash_Blake2b_32_digest(state, digest_1);

    // 2/2 Include `World!` into the hash calculation and
    // obtain the final hash of "Hello, World!".
    Hacl_Hash_Blake2b_32_update(state, (uint8_t*)chunk_2, chunk_2_size);
    Hacl_Hash_Blake2b_32_digest(state, digest_2);

    // Cleanup
    Hacl_Hash_Blake2b_32_free(state);

    print_hex_ln(HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX, digest_1);
    print_hex_ln(HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX, digest_2);
    // ANCHOR_END(example streaming)

    bytes expected_digest_1 = from_hex(
      "17ec82285d5efd15c7f3cb6ceeea15dbb0588350729932fbdddc8c37e347999d7a125003"
      "df087dd3a6f5983fa87ce2dfa162cc590005c7ff872732788cbf0626");
    bytes expected_digest_2 = from_hex(
      "7dfdb888af71eae0e6a6b751e8e3413d767ef4fa52a7993daa9ef097f7aa3d949199c113"
      "caa37c94f80cf3b22f7d9d6e4f5def4ff927830cffe4857c34be3d89");

    EXPECT_EQ(strncmp((char*)digest_1,
                      (char*)expected_digest_1.data(),
                      HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX),
              0);
    EXPECT_EQ(strncmp((char*)digest_2,
                      (char*)expected_digest_2.data(),
                      HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX),
              0);
  }
}

// -----------------------------------------------------------------------------

class TestCase
{
public:
  size_t out_len;
  bytes digest;
  bytes input;
  bytes key;
};

ostream&
operator<<(ostream& os, const TestCase& test)
{
  os << "TestCase {" << endl
     << "\t.out_len = " << test.out_len << endl
     << "\t.digest = " << bytes_to_hex(test.digest) << endl
     << "\t.input = " << bytes_to_hex(test.input) << endl
     << "\t.key = " << bytes_to_hex(test.key) << endl
     << "}" << endl;
  return os;
}

vector<TestCase>
read_blake2b_json(string path)
{
  ifstream json_test_file(path);
  json test_vectors;
  json_test_file >> test_vectors;

  vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors.items()) {
    auto test_case = test.value();
    auto out_len = test_case["outlen"];
    auto digest = from_hex(test_case["out"]);
    auto input = from_hex(test_case["input"]);
    auto key = from_hex(test_case["key"]);

    tests_out.push_back({ out_len, digest, input, key });
  }

  return tests_out;
}

vector<TestCase>
read_official_json(string path)
{
  // Read JSON test vector
  ifstream json_test_file(path);
  json test_vectors;
  json_test_file >> test_vectors;

  vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors.items()) {
    auto test_case = test.value();
    if (test_case["hash"] == "blake2b") {
      string digest_str = test_case["out"];
      auto digest = from_hex(digest_str);
      auto out_len = digest_str.length() / 2;
      auto input = from_hex(test_case["in"]);
      auto key = from_hex(test_case["key"]);

      tests_out.push_back({ out_len, digest, input, key });
    } else if (test_case["hash"] == "blake2bp") {
      // Skipping
    } else if (test_case["hash"] == "blake2xb") {
      // Skipping
    } else if (test_case["hash"] == "blake2s") {
      // Skipping
    } else if (test_case["hash"] == "blake2sp") {
      // Skipping
    } else if (test_case["hash"] == "blake2xs") {
      // Skipping
    } else {
      throw "Unexpected hash value.";
    }
  }

  return tests_out;
}

class Blake2b : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Blake2b, KAT)
{
  auto test = GetParam();

  {
    bytes got_digest(test.out_len);

    Hacl_Hash_Blake2b_32_hash_with_key(got_digest.data(),
			               test.out_len,
                                       test.input.data(),
                                       test.input.size(),
                                       test.key.data(),
                                       test.key.size());

    bool outcome =
      compare_and_print(test.out_len, got_digest.data(), test.digest.data());

    EXPECT_TRUE(outcome);
  }
}

class Blake2bStreaming
  : public ::testing::TestWithParam<tuple<TestCase, vector<size_t>>>
{};

TEST_P(Blake2bStreaming, KAT)
{
  TestCase test_case;
  vector<size_t> lengths;
  tie(test_case, lengths) = GetParam();

  {
    // Skip tests with key.
    if (test_case.key.size() != 0) {
      return;
    }

    bytes got_digest(64);

    // Init
    Hacl_Hash_Blake2b_32_state_t* state = Hacl_Hash_Blake2b_32_malloc();
    Hacl_Hash_Blake2b_32_reset(state);

    // Update
    for (auto chunk : split_by_index_list(test_case.input, lengths)) {
      Hacl_Hash_Blake2b_32_update(state, chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Hash_Blake2b_32_digest(state, got_digest.data());
    Hacl_Hash_Blake2b_32_free(state);

    EXPECT_EQ(test_case.digest, got_digest);
  }

#ifdef HACL_CAN_COMPILE_VEC256
  {
    hacl_init_cpu_features();

    if (hacl_vec256_support()) {
      bytes got_hash(64);

      // Init
      Hacl_Hash_Blake2b_Simd256_state_t* state =
        Hacl_Hash_Blake2b_Simd256_malloc();
      Hacl_Hash_Blake2b_Simd256_reset(state);

      // Update
      Hacl_Hash_Blake2b_Simd256_update(
        state, test_case.input.data(), test_case.input.size());

      // Finish
      Hacl_Hash_Blake2b_Simd256_digest(state, got_hash.data());
      Hacl_Hash_Blake2b_Simd256_free(state);

      EXPECT_EQ(test_case.digest, got_hash);
    } else {
      printf(" ! Vec256 was compiled but AVX2 is not available on this CPU.\n");
    }
  }
#endif
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

  if (test.key.size() != 0) {
    return;
  }

  {
    bytes got_digest(test.digest.size(), 0);

    EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_Blake2B,
                                    got_digest.data(),
                                    test.input.data(),
                                    test.input.size());

    EXPECT_EQ(test.digest, got_digest);
  }

  // Streaming
  {
    bytes got_digest(test.digest.size(), 0);

    EverCrypt_Hash_Incremental_hash_state* state =
      EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_Blake2B);

    EverCrypt_Hash_Incremental_reset(state);

    for (auto chunk : split_by_index_list(test.input, lengths)) {
      EverCrypt_Hash_Incremental_update(state, chunk.data(), chunk.size());
    }

    EverCrypt_Hash_Incremental_digest(state, got_digest.data());
    EverCrypt_Hash_Incremental_free(state);

    EXPECT_EQ(test.digest, got_digest);
  }
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  Kat,
  Blake2b,
  ::testing::ValuesIn(read_blake2b_json("blake2b.json")));

INSTANTIATE_TEST_SUITE_P(
  Official,
  Blake2b,
  ::testing::ValuesIn(read_official_json("official.json")));

INSTANTIATE_TEST_SUITE_P(
  Vectors,
  Blake2b,
  ::testing::ValuesIn(read_official_json("vectors2b.json")));

INSTANTIATE_TEST_SUITE_P(
  Kat,
  Blake2bStreaming,
  ::testing::Combine(::testing::ValuesIn(read_blake2b_json("blake2b.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Official,
  Blake2bStreaming,
  ::testing::Combine(::testing::ValuesIn(read_official_json("official.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Vectors,
  Blake2bStreaming,
  ::testing::Combine(::testing::ValuesIn(read_official_json("vectors2b.json")),
                     ::testing::ValuesIn(make_lengths())));

// ----- EverCrypt -------------------------------------------------------------

// Blake2 can use HACL's VEC128 and VEC256 features.
// These features translate to avx and avx2 on Intel machines.
vector<EverCryptConfig>
generate_blake2b_configs()
{
  vector<EverCryptConfig> configs;

  for (uint32_t i = 0; i < 4; ++i) {
    configs.push_back(EverCryptConfig{
      .disable_adx = false,
      .disable_aesni = false,
      .disable_avx = (i & 1) != 0,
      .disable_avx2 = (i & 2) != 0,
      .disable_avx512 = false,
      .disable_bmi2 = false,
      .disable_movbe = false,
      .disable_pclmulqdq = false,
      .disable_rdrand = false,
      .disable_shaext = false,
      .disable_sse = false,
    });
  }

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  ECBlake2b,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_blake2b_configs()),
    ::testing::Combine(::testing::ValuesIn(read_blake2b_json("blake2b.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  ECOfficial,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_blake2b_configs()),
    ::testing::Combine(::testing::ValuesIn(read_official_json("official.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  ECVectors,
  EverCryptSuiteTestCase,
  ::testing::Combine(::testing::ValuesIn(generate_blake2b_configs()),
                     ::testing::Combine(::testing::ValuesIn(
                                          read_official_json("vectors2b.json")),
                                        ::testing::ValuesIn(make_lengths()))));
