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
#include "blake2_vectors.h"
#include "config.h"
#include "util.h"

#include "EverCrypt_Hash.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_256.h"
#endif

#define VALE                                                                   \
  TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64 ||                         \
    TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X86

#if VALE
// Only include this for checking CPU flags.
#include "Vale.h"
#endif

using json = nlohmann::json;

// Function pointer to multiplex between the different implementations.
typedef void (
  *test_blake)(uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*);

bool
test_blake2b(test_blake blake,
             size_t input_len,
             uint8_t* input,
             size_t key_len,
             uint8_t* key,
             size_t expected_len,
             uint8_t* expected)
{
  bytes comp(expected_len, 0);
  (*blake)(expected_len, comp.data(), input_len, input, key_len, key);
  return compare_and_print(expected_len, comp.data(), expected);
}

class Blake2bTesting : public ::testing::TestWithParam<blake2_test_vector>
{};

TEST_P(Blake2bTesting, TryTestVectors)
{
  const blake2_test_vector& vectors2b(GetParam());
  bool test = test_blake2b(&Hacl_Blake2b_32_blake2b,
                           vectors2b.input_len,
                           vectors2b.input,
                           vectors2b.key_len,
                           vectors2b.key,
                           vectors2b.expected_len,
                           vectors2b.expected);
  EXPECT_TRUE(test);

#ifdef HACL_CAN_COMPILE_VEC256
  // We might have compiled vec256 blake2b but don't have it available on the
  // CPU when running now.
  if (hacl_vec256_support()) {
    test = test_blake2b(&Hacl_Blake2b_256_blake2b,
                        vectors2b.input_len,
                        vectors2b.input,
                        vectors2b.key_len,
                        vectors2b.key,
                        vectors2b.expected_len,
                        vectors2b.expected);
    EXPECT_TRUE(test);
  } else {
    printf(" ! Vec256 was compiled but AVX2 is not available on this CPU.\n");
  }
#endif
}

INSTANTIATE_TEST_SUITE_P(TestVectors,
                         Blake2bTesting,
                         ::testing::ValuesIn(vectors2b));

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
read_json()
{

  // Read JSON test vector
  std::string test_dir = "blake2b.json";
  std::ifstream json_test_file(test_dir);
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
    if (test_case["hash"] == "blake2b") {
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

class Blake2bKAT : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Blake2bKAT, TryKAT)
{
  // Initialize CPU feature detection
  hacl_init_cpu_features();
  EverCrypt_AutoConfig2_init();
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* input = const_cast<uint8_t*>(test_case.input.data());
  uint8_t* key = const_cast<uint8_t*>(test_case.key.data());
  uint8_t* digest = const_cast<uint8_t*>(test_case.digest.data());

  bool test = test_blake2b(&Hacl_Blake2b_32_blake2b,
                           test_case.input.size(),
                           input,
                           test_case.key.size(),
                           key,
                           test_case.out_len,
                           digest);
  EXPECT_TRUE(test);

  if (test_case.key.size() == 0) {
    bytes digest_evercrypt(test_case.out_len, 0);
    uint8_t* input = const_cast<uint8_t*>(test_case.input.data());
    EverCrypt_Hash_hash(EverCrypt_Hash_Blake2B_s,
                        digest_evercrypt.data(),
                        input,
                        test_case.input.size());
    EXPECT_EQ(digest_evercrypt, test_case.digest);
  }
}

INSTANTIATE_TEST_SUITE_P(Kat, Blake2bKAT, ::testing::ValuesIn(read_json()));
INSTANTIATE_TEST_SUITE_P(OfficialKat,
                         Blake2bKAT,
                         ::testing::ValuesIn(read_official_json()));
