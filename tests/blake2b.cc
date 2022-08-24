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
#include "Hacl_Hash_Blake2.h"
#include "Hacl_Streaming_Blake2.h"
#include "config.h"
#include "evercrypt.h"
#include "hacl-cpu-features.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_256.h"
#include "Hacl_Streaming_Blake2b_256.h"
#endif

#define VALE                                                                   \
  TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64 ||                         \
    TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X86

#if VALE
// Only include this for checking CPU flags.
#include "Vale.h"
#endif

using json = nlohmann::json;

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

std::vector<TestCase>
read_blake2b_json(std::string path)
{
  std::ifstream json_test_file(path);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

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

std::vector<TestCase>
read_official_json(std::string path)
{
  // Read JSON test vector
  std::ifstream json_test_file(path);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors.items()) {
    auto test_case = test.value();
    if (test_case["hash"] == "blake2b") {
      std::string digest_str = test_case["out"];
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

    Hacl_Blake2b_32_blake2b(test.out_len,
                            got_digest.data(),
                            test.input.size(),
                            test.input.data(),
                            test.key.size(),
                            test.key.data());

    bool outcome =
      compare_and_print(test.out_len, got_digest.data(), test.digest.data());

    EXPECT_TRUE(outcome);
  }
}

class Blake2bStreaming : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Blake2bStreaming, KAT)
{
  auto test_case = GetParam();

  {
    // Skip tests with key.
    if (test_case.key.size() != 0) {
      return;
    }

    bytes got_digest(64);

    // Init
    Hacl_Streaming_Blake2_blake2b_32_state_s* state =
      Hacl_Streaming_Blake2_blake2b_32_no_key_create_in();
    Hacl_Streaming_Blake2_blake2b_32_no_key_init(state);

    // Update
    Hacl_Streaming_Blake2_blake2b_32_no_key_update(
      state, test_case.input.data(), test_case.input.size());

    // Finish
    Hacl_Streaming_Blake2_blake2b_32_no_key_finish(state, got_digest.data());
    Hacl_Streaming_Blake2_blake2b_32_no_key_free(state);

    EXPECT_EQ(test_case.digest, got_digest);
  }

#ifdef HACL_CAN_COMPILE_VEC256
  {
    hacl_init_cpu_features();

    if (hacl_vec256_support()) {
      // TODO: Enable this. See
      // https://github.com/project-everest/hacl-star/issues/586
      //
      //    bytes got_hash(64);
      //
      //    // Init
      //    Hacl_Streaming_Blake2b_256_blake2b_256_state* state =
      //      Hacl_Streaming_Blake2b_256_blake2b_256_no_key_create_in();
      //    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_init(state);
      //
      //    // Update
      //    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_update(
      //      state, test_case.input.data(), test_case.input.size());
      //
      //    // Finish
      //    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_finish(state,
      //                                                         got_hash.data());
      //    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_free(state);
      //
      //    EXPECT_EQ(test_case.digest, got_hash);
    } else {
      printf(" ! Vec256 was compiled but AVX2 is not available on this CPU.\n");
    }
  }
#endif
}

// ----- EverCrypt -------------------------------------------------------------

typedef EverCryptSuite<TestCase> EverCryptSuiteTestCase;

TEST_P(EverCryptSuiteTestCase, HashTest)
{
  EverCryptConfig config;
  TestCase test;
  tie(config, test) = this->GetParam();

  if (test.key.size() != 0) {
    return;
  }

  {
    bytes got_digest(test.digest.size(), 0);

    EverCrypt_Hash_hash(Spec_Hash_Definitions_Blake2B,
                        got_digest.data(),
                        test.input.data(),
                        test.input.size());

    EXPECT_EQ(test.digest, got_digest);
  }

  // TODO: https://github.com/project-everest/hacl-star/issues/586
  // // Streaming
  // {
  //   bytes got_digest(test.digest.size(), 0);

  //   Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____* state =
  //     EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_Blake2B);

  //   EverCrypt_Hash_Incremental_init(state);
  //   EverCrypt_Hash_Incremental_update(
  //     state, test.input.data(), test.input.size());
  //   EverCrypt_Hash_Incremental_finish(state, got_digest.data());
  //   EverCrypt_Hash_Incremental_free(state);

  //   EXPECT_EQ(test.digest, got_digest);
  // }
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
  ::testing::ValuesIn(read_blake2b_json("blake2b.json")));

INSTANTIATE_TEST_SUITE_P(
  Official,
  Blake2bStreaming,
  ::testing::ValuesIn(read_official_json("official.json")));

INSTANTIATE_TEST_SUITE_P(
  Vectors,
  Blake2bStreaming,
  ::testing::ValuesIn(read_official_json("vectors2b.json")));

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
  ::testing::Combine(::testing::ValuesIn(generate_blake2b_configs()),
                     ::testing::ValuesIn(read_blake2b_json("blake2b.json"))));

INSTANTIATE_TEST_SUITE_P(
  ECOfficial,
  EverCryptSuiteTestCase,
  ::testing::Combine(::testing::ValuesIn(generate_blake2b_configs()),
                     ::testing::ValuesIn(read_official_json("official.json"))));

INSTANTIATE_TEST_SUITE_P(
  ECVectors,
  EverCryptSuiteTestCase,
  ::testing::Combine(
    ::testing::ValuesIn(generate_blake2b_configs()),
    ::testing::ValuesIn(read_official_json("vectors2b.json"))));
