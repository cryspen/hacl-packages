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

#include "hacl-cpu-features.h"

#include "Hacl_Hash_Blake2.h"
#include "Hacl_Streaming_Blake2.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#include "Hacl_Streaming_Blake2s_128.h"
#endif

#include "util.h"

#include "EverCrypt_Hash.h"

using json = nlohmann::json;

typedef struct
{
  size_t out_len;
  bytes digest;
  bytes input;
  bytes key;
} TestCase;

class Blake2s : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Blake2s, TryKAT)
{
  auto test = GetParam();

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
      Hacl_Streaming_Blake2_blake2s_32_no_key_update(
        state, test.input.data(), test.input.size());

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
      // TODO: Enable this. See https://github.com/project-everest/hacl-star/issues/586
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

      EverCrypt_Hash_hash(EverCrypt_Hash_Blake2S_s,
                          got_digest.data(),
                          test.input.data(),
                          test.input.size());

      EXPECT_EQ(got_digest, test.digest);
    }
  }
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
    if (test_case["hash"] == "blake2s") {
      std::string digest_str = test_case["out"];
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
      std::cout << test_case["hash"] << std::endl;
      throw "Unexpected hash value.";
    }
  }

  return tests_out;
}

INSTANTIATE_TEST_SUITE_P(
  Official,
  Blake2s,
  ::testing::ValuesIn(read_official_json("official.json")));

INSTANTIATE_TEST_SUITE_P(
  Vectors,
  Blake2s,
  ::testing::ValuesIn(read_official_json("vectors2s.json")));
