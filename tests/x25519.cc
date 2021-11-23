#include <fstream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "Hacl_Curve25519_51.h"
#include "curve25519_vectors.h"

#define VALE TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64

#if VALE
#include "Hacl_Curve25519_64.h"
#endif

#include "config.h"
#include "util.h"

using json = nlohmann::json;

#define bytes std::vector<uint8_t>

TEST(x25519Test, HaclTest)
{
  for (int i = 0; i < sizeof(vectors) / sizeof(curve25519_test_vector); ++i) {
    uint8_t comp[32] = { 0 };
    Hacl_Curve25519_51_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
    EXPECT_TRUE(print_result(32, comp, vectors[i].secret));

#if VALE
    memset(comp, 0, 32);
    Hacl_Curve25519_64_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
    EXPECT_TRUE(print_result(32, comp, vectors[i].secret));
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
  std::string test_dir = TEST_DIR;
  test_dir += "/x25519_test.json";
  std::ifstream json_test_file(test_dir);
  json test_vectors;
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
