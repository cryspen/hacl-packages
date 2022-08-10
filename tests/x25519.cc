/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>

#include "EverCrypt_AutoConfig2.h"
#include "hacl-cpu-features.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#define VALE TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64

#include "Hacl_Curve25519_51.h"
#include "curve25519_vectors.h"

#if VALE
#include "Hacl_Curve25519_64.h"
#include "Vale.h"
#endif

#include "config.h"
#include "util.h"

#define bytes std::vector<uint8_t>

TEST(x25519Test, HaclTest)
{
  // Initialize CPU feature detection
  hacl_init_cpu_features();
  EverCrypt_AutoConfig2_init();

  for (int i = 0; i < sizeof(vectors) / sizeof(curve25519_test_vector); ++i) {
    uint8_t comp[32] = { 0 };
    Hacl_Curve25519_51_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
    EXPECT_TRUE(compare_and_print(32, comp, vectors[i].secret));

#if VALE
    // We have vale compiled. But we have to check that we can actually use it
    // when calling HACL functions.
    if (vale_x25519_support()) {
      memset(comp, 0, 32);
      Hacl_Curve25519_64_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
      EXPECT_TRUE(compare_and_print(32, comp, vectors[i].secret));
    } else {
      printf(" ! Vale is available but ADX and/or BMI2 extensions are "
             "missing.\n");
    }
#endif
  }
}

//=== Wycheproof tests ====

typedef struct
{
  bytes public_key;
  bytes private_key;
  bytes shared;
  bool valid;
} TestCase;

std::vector<TestCase>
read_json()
{

  // Read JSON test vector
  std::string test_dir = "x25519_test.json";
  std::ifstream json_test_file(test_dir);
  nlohmann::json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();

    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto private_key = from_hex(test_case_value["private"]);
      auto public_key = from_hex(test_case_value["public"]);
      auto shared = from_hex(test_case_value["shared"]);
      auto result = test_case_value["result"];
      bool valid = result == "valid" || result == "acceptable";

      tests_out.push_back({ public_key, private_key, shared, valid });
    }
  }

  return tests_out;
}

class X25519Wycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(X25519Wycheproof, TryWycheproof)
{
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* private_key = const_cast<uint8_t*>(test_case.private_key.data());
  uint8_t* public_key = const_cast<uint8_t*>(test_case.public_key.data());

  uint8_t computed_shared[32] = { 0 };
  Hacl_Curve25519_51_ecdh(computed_shared, private_key, public_key);
  if (test_case.valid) {
    EXPECT_EQ(std::vector<uint8_t>(computed_shared, computed_shared + 32),
              test_case.shared);
  } else {
    EXPECT_NE(std::vector<uint8_t>(computed_shared, computed_shared + 32),
              test_case.shared);
  }
}

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         X25519Wycheproof,
                         ::testing::ValuesIn(read_json()));
