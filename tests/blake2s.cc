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
#include "Hacl_Hash_Blake2.h"
// ANCHOR_END(example header)
#include "Hacl_Streaming_Blake2.h"
#include "evercrypt.h"
#include "hacl-cpu-features.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#include "Hacl_Streaming_Blake2s_128.h"
#endif

using json = nlohmann::json;
using namespace std;

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

// -----------------------------------------------------------------------------

TEST(ApiTestSuite, ApiTest)
{
  // ANCHOR(example)
  // Reserve memory for a 32 byte digest, i.e.,
  // for a BLAKE2s run with full 256-bit output.
  uint32_t output_len = 32;
  uint8_t output[32];

  // The message we want to hash.
  const char* message = "Hello, HACL Packages!";
  uint32_t message_len = strlen(message);

  // BLAKE2s can be used as an HMAC, i.e., with a key.
  // We don't want to use a key here and thus provide a zero-sized key.
  uint32_t key_len = 0;
  uint8_t* key = 0;

  Hacl_Blake2s_32_blake2s(
    output_len, output, message_len, (uint8_t*)message, key_len, key);

  print_hex_ln(output_len, output);
  // ANCHOR_END(example)
}

// -----------------------------------------------------------------------------

class Blake2s : public ::testing::TestWithParam<tuple<TestCase, vector<size_t>>>
{};

TEST_P(Blake2s, TryKAT)
{
  TestCase test;
  vector<size_t> lengths;
  tie(test, lengths) = GetParam();

  {
    bytes got_digest(test.out_len);

    Hacl_Blake2s_32_blake2s(test.out_len,
                            got_digest.data(),
                            test.input.size(),
                            test.input.data(),
                            test.key.size(),
                            test.key.data());

    bool outcome = false;
    outcome =
      compare_and_print(test.out_len, got_digest.data(), test.digest.data());

    EXPECT_TRUE(outcome);
  }

  // Streaming variant.
  {
    bytes got_digest(test.out_len);

    if (test.key.size() == 0) {
      // Init
      Hacl_Streaming_Blake2_blake2s_32_state* state =
        Hacl_Streaming_Blake2_blake2s_32_no_key_create_in();
      Hacl_Streaming_Blake2_blake2s_32_no_key_init(state);

      // Update
      for (auto chunk : split_by_index_list(test.input, lengths)) {
        Hacl_Streaming_Blake2_blake2s_32_no_key_update(
          state, chunk.data(), chunk.size());
      }

      // Finish
      Hacl_Streaming_Blake2_blake2s_32_no_key_finish(state, got_digest.data());
      Hacl_Streaming_Blake2_blake2s_32_no_key_free(state);

      bool outcome = compare_and_print(
        test.digest.size(), got_digest.data(), test.digest.data());

      EXPECT_TRUE(outcome);
    }
  }

#ifdef HACL_CAN_COMPILE_VEC128
  {
    hacl_init_cpu_features();

    if (hacl_vec128_support()) {
      // TODO: Enable this. See
      // https://github.com/project-everest/hacl-star/issues/586
      //
      //    Hacl_Blake2s_128_blake2s(expected_len, got_digest.data(), input_len,
      //    input, key_len, key); outcome = outcome &&
      //    compare_and_print(expected_len, got_digest.data(), expected);
      //
      //    // Streaming variant.
      //    if (key_len == 0) {
      //      // Init
      //      Hacl_Streaming_Blake2s_128_blake2s_128_state_s* state =
      //        Hacl_Streaming_Blake2s_128_blake2s_128_no_key_create_in();
      //
      //      // Update
      //      Hacl_Streaming_Blake2s_128_blake2s_128_no_key_update(state, input,
      //      input_len);
      //
      //      // Finish
      //      Hacl_Streaming_Blake2s_128_blake2s_128_no_key_finish(state,
      //      got_digest.data());
      //
      //      outcome = outcome && compare_and_print(expected_len,
      //      got_digest.data(), expected);
      //    }
    } else {
      printf(" !!! NO VEC128 SUPPORT ON THIS MACHINE! !!!\n");
    }
  }
#endif

  // EverCrypt
  {
    EverCrypt_AutoConfig2_init();

    if (test.key.size() == 0) {
      bytes got_digest(test.out_len, 0);

      EverCrypt_Hash_hash(Spec_Hash_Definitions_Blake2S,
                          got_digest.data(),
                          test.input.data(),
                          test.input.size());

      EXPECT_EQ(got_digest, test.digest);
    }
  }
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
    if (test_case["hash"] == "blake2s") {
      string digest_str = test_case["out"];
      auto digest = from_hex(digest_str);
      auto out_len = digest_str.length() / 2;
      auto input = from_hex(test_case["in"]);
      auto key = from_hex(test_case["key"]);

      tests_out.push_back({ out_len, digest, input, key });
    } else if (test_case["hash"] == "blake2sp") {
      // Skipping
    } else if (test_case["hash"] == "blake2xs") {
      // Skipping
    } else if (test_case["hash"] == "blake2b") {
      // Skipping
    } else if (test_case["hash"] == "blake2bp") {
      // Skipping
    } else if (test_case["hash"] == "blake2xb") {
      // Skipping
    } else {
      cout << test_case["hash"] << endl;
      throw "Unexpected hash value.";
    }
  }

  return tests_out;
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

    EverCrypt_Hash_hash(Spec_Hash_Definitions_Blake2S,
                        got_digest.data(),
                        test.input.data(),
                        test.input.size());

    EXPECT_EQ(test.digest, got_digest);
  }

  // Streaming
  {
    bytes got_digest(test.digest.size(), 0);

    Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____* state =
      EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_Blake2S);

    EverCrypt_Hash_Incremental_init(state);
    for (auto chunk : split_by_index_list(test.input, lengths)) {
      EverCrypt_Hash_Incremental_update(state, chunk.data(), chunk.size());
    }
    EverCrypt_Hash_Incremental_finish(state, got_digest.data());
    EverCrypt_Hash_Incremental_free(state);

    EXPECT_EQ(test.digest, got_digest);
  }
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  Official,
  Blake2s,
  ::testing::Combine(::testing::ValuesIn(read_official_json("official.json")),
                     ::testing::ValuesIn(make_lengths())));

INSTANTIATE_TEST_SUITE_P(
  Vectors,
  Blake2s,
  ::testing::Combine(::testing::ValuesIn(read_official_json("vectors2s.json")),
                     ::testing::ValuesIn(make_lengths())));

// ----- EverCrypt -------------------------------------------------------------

// Blake2 can use HACL's VEC128 and VEC256 features.
// These features translate to avx and avx2 on Intel machines.
vector<EverCryptConfig>
generate_blake2s_configs()
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
  Official,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_blake2s_configs()),
    ::testing::Combine(::testing::ValuesIn(read_official_json("official.json")),
                       ::testing::ValuesIn(make_lengths()))));

INSTANTIATE_TEST_SUITE_P(
  Vectors,
  EverCryptSuiteTestCase,
  ::testing::Combine(::testing::ValuesIn(generate_blake2s_configs()),
                     ::testing::Combine(::testing::ValuesIn(
                                          read_official_json("vectors2s.json")),
                                        ::testing::ValuesIn(make_lengths()))));
