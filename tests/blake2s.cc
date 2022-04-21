/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <fstream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "hacl-cpu-features.h"

#include "Hacl_Hash_Blake2.h"
#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#endif

#include "blake2_vectors.h"
#include "util.h"

#include "EverCrypt_Hash.h"

using json = nlohmann::json;

bool
print_test2s(int in_len,
             uint8_t* in,
             int key_len,
             uint8_t* key,
             int exp_len,
             uint8_t* exp)
{
  bytes comp(exp_len, 0);
  bool ok = false;

  Hacl_Blake2s_32_blake2s(exp_len, comp.data(), in_len, in, key_len, key);
  ok = compare_and_print(exp_len, comp.data(), exp);

#ifdef HACL_CAN_COMPILE_VEC128
  // We might have compiled vec128 blake2s but don't have it available on the
  // CPU when running now.
  if (hacl_vec128_support()) {
    Hacl_Blake2s_128_blake2s(exp_len, comp.data(), in_len, in, key_len, key);
    ok = ok && compare_and_print(exp_len, comp.data(), exp);
  } else {
    printf(" !!! NO VEC128 SUPPORT ON THIS MACHINE! !!!\n");
    ok = ok && true;
  }
#endif

  return ok;
}

class Blake2sTesting : public ::testing::TestWithParam<blake2_test_vector>
{};

TEST_P(Blake2sTesting, TryTestVectors)
{
  const blake2_test_vector& vectors2s(GetParam());
  bool test = print_test2s(vectors2s.input_len,
                           vectors2s.input,
                           vectors2s.key_len,
                           vectors2s.key,
                           vectors2s.expected_len,
                           vectors2s.expected);
  EXPECT_TRUE(test);
}

INSTANTIATE_TEST_SUITE_P(TestVectors,
                         Blake2sTesting,
                         ::testing::ValuesIn(vectors2s));

// === Test vectors === //

#define bytes std::vector<uint8_t>

typedef struct
{
  size_t out_len;
  bytes digest;
  bytes input;
  bytes key;
} TestCase;

std::vector<TestCase>
read_official_json()
{

  // Read JSON test vector
  std::string test_dir = "official.json";
  std::ifstream json_test_file(test_dir);
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
    }
  }

  return tests_out;
}

class Blake2sKAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Blake2sKAT, TryKAT)
{
  // Initialize CPU feature detection
  hacl_init_cpu_features();
  EverCrypt_AutoConfig2_init();
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* input = const_cast<uint8_t*>(test_case.input.data());
  uint8_t* key = const_cast<uint8_t*>(test_case.key.data());
  uint8_t* digest = const_cast<uint8_t*>(test_case.digest.data());

  bool test = print_test2s(test_case.input.size(),
                           input,
                           test_case.key.size(),
                           key,
                           test_case.out_len,
                           digest);
  EXPECT_TRUE(test);

  if (test_case.key.size() == 0) {
    bytes digest_evercrypt(test_case.out_len, 0);
    uint8_t* input = const_cast<uint8_t*>(test_case.input.data());
    EverCrypt_Hash_hash(EverCrypt_Hash_Blake2S_s,
                        digest_evercrypt.data(),
                        input,
                        test_case.input.size());
    EXPECT_EQ(digest_evercrypt, test_case.digest);
  }
}

INSTANTIATE_TEST_SUITE_P(OfficialKat,
                         Blake2sKAT,
                         ::testing::ValuesIn(read_official_json()));
