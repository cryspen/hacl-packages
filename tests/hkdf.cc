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

#include "EverCrypt_HKDF.h"
#include "EverCrypt_Hash.h"
#include "Hacl_HKDF.h"
#include "Hacl_Hash_Base.h"
#include "evercrypt.h"
#include "util.h"

// ANCHOR(EXAMPLE DEFINE)
#define HACL_KDF_HKDF_BLAKE2B_PRK_LEN 64
#define HACL_KDF_HKDF_BLAKE2S_PRK_LEN 32
#define HACL_KDF_HKDF_SHA2_256_PRK_LEN 32
#define HACL_KDF_HKDF_SHA2_512_PRK_LEN 64
// ANCHOR_END(EXAMPLE DEFINE)

using json = nlohmann::json;

TEST(ApiSuite, ApiTest)
{
  // ANCHOR(EXAMPLE)
  // Example: We assume that we have some input keying material ...
  uint8_t ikm[128];
  uint32_t ikm_len = 128;
  generate_random(ikm, 128);

  // ... and a salt.
  const char* salt = "example";
  uint32_t salt_len = strlen(salt);

  // Extract a fixed-length pseudo-random key from `ikm`.
  uint8_t prk[HACL_KDF_HKDF_SHA2_256_PRK_LEN];

  Hacl_HKDF_extract_sha2_256(prk, (uint8_t*)salt, salt_len, ikm, ikm_len);

  // Expand pseudo-random key to desired length
  // and write it to `okm` (output keying material).
  uint8_t okm[1337];
  uint32_t okm_len = 1337;

  // We don't provide specific information here.
  const char* info = "";
  uint32_t info_len = 0;

  Hacl_HKDF_expand_sha2_256(okm,
                            prk,
                            HACL_KDF_HKDF_SHA2_256_PRK_LEN,
                            (uint8_t*)info,
                            info_len,
                            okm_len);
  // ANCHOR_END(EXAMPLE)
}

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

// -----------------------------------------------------------------------------

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
  } else if (test.hash == "SHA-384") {
    // Not supported.
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

// -----------------------------------------------------------------------------

void
test_hkdf(TestCase& test, Spec_Hash_Definitions_hash_alg alg)
{
  bytes got_prk(Hacl_Hash_Definitions_hash_len(alg));

  EverCrypt_HKDF_extract(alg,
                         got_prk.data(),
                         test.salt.data(),
                         test.salt.size(),
                         test.IKM.data(),
                         test.IKM.size());

  if (test.PRK.size() != 0) {
    EXPECT_EQ(test.PRK, got_prk);
  }

  bytes got_OKM(test.L);

  EverCrypt_HKDF_expand(alg,
                        got_OKM.data(),
                        got_prk.data(),
                        got_prk.size(),
                        test.info.data(),
                        test.info.size(),
                        test.L);

  EXPECT_EQ(test.OKM, got_OKM);
}

typedef EverCryptSuite<TestCase> HKDFSuiteEverCrypt;

TEST_P(HKDFSuiteEverCrypt, TestCase)
{
  EverCryptConfig config;
  TestCase test;
  tie(config, test) = this->GetParam();

  // We do not forbid OKM > 255 * HashLen in Hacl_HKDF_* currently.
  // See https://github.com/cryspen/hacl-packages/issues/123
  if (!test.valid) {
    return;
  }

  if (test.hash == "SHA-1") {
    test_hkdf(test, Spec_Hash_Definitions_SHA1);
  } else if (test.hash == "SHA-256") {
    test_hkdf(test, Spec_Hash_Definitions_SHA2_256);
  } else if (test.hash == "SHA-384") {
    test_hkdf(test, Spec_Hash_Definitions_SHA2_384);
  } else if (test.hash == "SHA-512") {
    test_hkdf(test, Spec_Hash_Definitions_SHA2_512);
  } else if (test.hash == "BLAKE2s") {
    test_hkdf(test, Spec_Hash_Definitions_Blake2S);
  } else if (test.hash == "BLAKE2b") {
    test_hkdf(test, Spec_Hash_Definitions_Blake2B);
  } else {
    FAIL() << "Unexpected value \"" << test.hash << "\" for `test.hash`";
  }
}

// -----------------------------------------------------------------------------

std::vector<TestCase>
read_json_rfc5869(string path)
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
read_json_wycheproof(string path)
{
  json tests_raw;
  std::ifstream file(path);
  file >> tests_raw;

  std::string hash = tests_raw["algorithm"];

  if (hash == "HKDF-SHA-256") {
    hash = "SHA-256";
  } else if (hash == "HKDF-SHA-384") {
    hash = "SHA-384";
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

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  Rfc5869,
  HKDFSuite,
  ::testing::ValuesIn(read_json_rfc5869("rfc5869.json")));

INSTANTIATE_TEST_SUITE_P(
  WycheproofSha256,
  HKDFSuite,
  ::testing::ValuesIn(read_json_wycheproof("hkdf_sha256_test.json")));

INSTANTIATE_TEST_SUITE_P(
  WycheproofSha512,
  HKDFSuite,
  ::testing::ValuesIn(read_json_wycheproof("hkdf_sha512_test.json")));

INSTANTIATE_TEST_SUITE_P(
  WycheproofBlake2s,
  HKDFSuite,
  ::testing::ValuesIn(read_json_rfc5869("hkdf_blake2s.json")));

INSTANTIATE_TEST_SUITE_P(
  WycheproofBlake2b,
  HKDFSuite,
  ::testing::ValuesIn(read_json_rfc5869("hkdf_blake2b.json")));

// -----------------------------------------------------------------------------

// Portable (depends on hash) --> SHA1, SHA2, Blake2 --> avx, avx2, shaext
vector<EverCryptConfig>
generate_hkdf_configs()
{
  vector<EverCryptConfig> configs;

  for (uint32_t i = 0; i < 8; ++i) {
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
      .disable_shaext = (i & 4) != 1,
      .disable_sse = false,
    });
  }

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  Rfc5869,
  HKDFSuiteEverCrypt,
  ::testing::Combine(::testing::ValuesIn(generate_hkdf_configs()),
                     ::testing::ValuesIn(read_json_rfc5869("rfc5869.json"))));

INSTANTIATE_TEST_SUITE_P(
  WycheproofSha256,
  HKDFSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_hkdf_configs()),
    ::testing::ValuesIn(read_json_wycheproof("hkdf_sha256_test.json"))));

INSTANTIATE_TEST_SUITE_P(
  WycheproofSha384,
  HKDFSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_hkdf_configs()),
    ::testing::ValuesIn(read_json_wycheproof("hkdf_sha384_test.json"))));

INSTANTIATE_TEST_SUITE_P(
  WycheproofSha512,
  HKDFSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_hkdf_configs()),
    ::testing::ValuesIn(read_json_wycheproof("hkdf_sha512_test.json"))));

INSTANTIATE_TEST_SUITE_P(
  WycheproofBlake2s,
  HKDFSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_hkdf_configs()),
    ::testing::ValuesIn(read_json_rfc5869("hkdf_blake2s.json"))));

INSTANTIATE_TEST_SUITE_P(
  WycheproofBlake2b,
  HKDFSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_hkdf_configs()),
    ::testing::ValuesIn(read_json_rfc5869("hkdf_blake2b.json"))));
