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

#include "Hacl_HKDF.h"
#include "Hacl_Spec.h"
#include "util.h"

using json = nlohmann::json;

typedef struct
{
  std::string comment;
  // A tcId of 0 indicates "not Wycheproof".
  uint32_t tcId;
  std::string hash;
  // 1) Input Keying Material
  bytes IKM;
  bytes salt;
  bytes info;
  // Length of OKM
  uint32_t L;
  // 2) A pseudorandom key (of HashLen octets)
  // Empty PRK means "not available".
  bytes PRK;
  // 3) Output Keying Material
  bytes OKM;
  bool valid;
} TestCase;

class HKDFSuite : public ::testing::TestWithParam<TestCase>
{};

TEST_P(HKDFSuite, TestCase)
{
  auto test = GetParam();
  std::cout << "# " << test.comment << std::endl;

  // We do not forbid OKM > 255 * HashLen in Hacl_HKDF_* currently.
  // See https://github.com/cryspen/hacl-packages/issues/123
  if (!test.valid) {
    return;
  }

  if (test.hash == "SHA-1") {
    // Not supported.
  } else if (test.hash == "SHA-256") {
    bytes got_prk = std::vector<uint8_t>(32);

    Hacl_HKDF_extract_sha2_256(got_prk.data(),
                               test.salt.data(),
                               test.salt.size(),
                               test.IKM.data(),
                               test.IKM.size());

    if (test.PRK.size() != 0) {
      EXPECT_EQ(test.PRK, got_prk);
    }

    bytes got_OKM = std::vector<uint8_t>(test.L);

    Hacl_HKDF_expand_sha2_256(got_OKM.data(),
                              got_prk.data(),
                              got_prk.size(),
                              test.info.data(),
                              test.info.size(),
                              test.L);

    EXPECT_EQ(test.OKM, got_OKM);
  } else if (test.hash == "SHA-512") {
    bytes got_prk = std::vector<uint8_t>(64);

    Hacl_HKDF_extract_sha2_512(got_prk.data(),
                               test.salt.data(),
                               test.salt.size(),
                               test.IKM.data(),
                               test.IKM.size());

    if (test.PRK.size() != 0) {
      EXPECT_EQ(test.PRK, got_prk);
    }

    bytes got_OKM = std::vector<uint8_t>(test.L);

    Hacl_HKDF_expand_sha2_512(got_OKM.data(),
                              got_prk.data(),
                              got_prk.size(),
                              test.info.data(),
                              test.info.size(),
                              test.L);

    EXPECT_EQ(test.OKM, got_OKM);
  } else if (test.hash == "BLAKE2s") {
    bytes got_prk = std::vector<uint8_t>(64);

    Hacl_HKDF_extract_blake2s_32(got_prk.data(),
                                 test.salt.data(),
                                 test.salt.size(),
                                 test.IKM.data(),
                                 test.IKM.size());

    if (test.PRK.size() != 0) {
      EXPECT_EQ(test.PRK, got_prk);
    }

    bytes got_OKM = std::vector<uint8_t>(test.L);

    Hacl_HKDF_expand_blake2s_32(got_OKM.data(),
                                got_prk.data(),
                                got_prk.size(),
                                test.info.data(),
                                test.info.size(),
                                test.L);

    EXPECT_EQ(test.OKM, got_OKM);
  } else if (test.hash == "BLAKE2b") {
    bytes got_prk = std::vector<uint8_t>(64);

    Hacl_HKDF_extract_blake2b_32(got_prk.data(),
                                 test.salt.data(),
                                 test.salt.size(),
                                 test.IKM.data(),
                                 test.IKM.size());

    if (test.PRK.size() != 0) {
      EXPECT_EQ(test.PRK, got_prk);
    }

    bytes got_OKM = std::vector<uint8_t>(test.L);

    Hacl_HKDF_expand_blake2b_32(got_OKM.data(),
                                got_prk.data(),
                                got_prk.size(),
                                test.info.data(),
                                test.info.size(),
                                test.L);

    EXPECT_EQ(test.OKM, got_OKM);
  } else {
    FAIL() << "Unexpected value \"" << test.hash << "\" for `test.hash`";
  }
}

std::vector<TestCase>
read_json_rfc5869(char* path)
{
  json tests_raw;
  std::ifstream file(path);
  file >> tests_raw;

  std::vector<TestCase> tests;

  for (auto& test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    std::string comment = test["comment"];
    std::string hash = test["hash"];
    bytes IKM = from_hex(test["IKM"]);
    bytes salt = from_hex(test["salt"]);
    bytes info = from_hex(test["info"]);
    uint32_t L = test["L"];
    bytes PRK = from_hex(test["PRK"]);
    bytes OKM = from_hex(test["OKM"]);

    auto c = TestCase{
      .comment = comment,
      // Not a Wycheproof test.
      .tcId = 0,
      .hash = hash,
      .IKM = IKM,
      .salt = salt,
      .info = info,
      .L = L,
      .PRK = PRK,
      .OKM = OKM,
      .valid = true,
    };

    tests.push_back(c);
  }

  return tests;
}

std::vector<TestCase>
read_json_wycheproof(char* path)
{
  json tests_raw;
  std::ifstream file(path);
  file >> tests_raw;

  std::string hash = tests_raw["algorithm"];

  if (hash == "HKDF-SHA-256") {
    hash = "SHA-256";
  } else if (hash == "HKDF-SHA-512") {
    hash = "SHA-512";
  } else if (hash == "BLAKE2s") {
    // Good
  } else if (hash == "BLAKE2b") {
    // Good
  } else {
    throw "Unexpected value.";
  }

  std::vector<TestCase> tests;

  for (auto& group_raw : tests_raw["testGroups"].items()) {
    auto group = group_raw.value();

    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();

      std::string comment = test["comment"];
      uint32_t tcId = test["tcId"];
      bytes IKM = from_hex(test["ikm"]);
      bytes salt = from_hex(test["salt"]);
      bytes info = from_hex(test["info"]);
      uint32_t L = test["size"];
      bytes PRK = std::vector<uint8_t>(0);
      bytes OKM = from_hex(test["okm"]);

      bool valid = false;
      if (test["result"] == "valid") {
        valid = true;
      } else if (test["result"] == "invalid") {
        valid = false;
      } else {
        throw "Unexpected value for \"result\".";
      }

      auto c = TestCase{
        .comment = comment,
        .tcId = tcId,
        .hash = hash,
        .IKM = IKM,
        .salt = salt,
        .info = info,
        .L = L,
        .PRK = PRK,
        .OKM = OKM,
        .valid = valid,
      };

      tests.push_back(c);
    }
  }

  return tests;
}

INSTANTIATE_TEST_SUITE_P(
  Rfc5869,
  HKDFSuite,
  ::testing::ValuesIn(read_json_rfc5869(const_cast<char*>("rfc5869.json"))));

INSTANTIATE_TEST_SUITE_P(WycheproofSha256,
                         HKDFSuite,
                         ::testing::ValuesIn(read_json_wycheproof(
                           const_cast<char*>("hkdf_sha256_test.json"))));

INSTANTIATE_TEST_SUITE_P(WycheproofSha512,
                         HKDFSuite,
                         ::testing::ValuesIn(read_json_wycheproof(
                           const_cast<char*>("hkdf_sha512_test.json"))));

INSTANTIATE_TEST_SUITE_P(WycheproofBlake2s,
                         HKDFSuite,
                         ::testing::ValuesIn(read_json_rfc5869(
                           const_cast<char*>("hkdf_blake2s.json"))));

INSTANTIATE_TEST_SUITE_P(WycheproofBlake2b,
                         HKDFSuite,
                         ::testing::ValuesIn(read_json_rfc5869(
                           const_cast<char*>("hkdf_blake2b.json"))));
