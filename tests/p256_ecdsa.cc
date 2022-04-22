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

#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "Hacl_P256.h"
#include "util.h"

using json = nlohmann::json;

uint8_t prKey[32U] = {
  (uint8_t)81U,  (uint8_t)155U, (uint8_t)66U,  (uint8_t)61U,  (uint8_t)113U,
  (uint8_t)95U,  (uint8_t)139U, (uint8_t)88U,  (uint8_t)31U,  (uint8_t)79U,
  (uint8_t)168U, (uint8_t)238U, (uint8_t)89U,  (uint8_t)244U, (uint8_t)119U,
  (uint8_t)26U,  (uint8_t)91U,  (uint8_t)68U,  (uint8_t)200U, (uint8_t)19U,
  (uint8_t)11U,  (uint8_t)78U,  (uint8_t)62U,  (uint8_t)172U, (uint8_t)202U,
  (uint8_t)84U,  (uint8_t)165U, (uint8_t)109U, (uint8_t)218U, (uint8_t)114U,
  (uint8_t)180U, (uint8_t)100U
};

uint8_t digest[32U] = {
  (uint8_t)28U,  (uint8_t)203U, (uint8_t)233U, (uint8_t)28U,  (uint8_t)7U,
  (uint8_t)95U,  (uint8_t)199U, (uint8_t)244U, (uint8_t)240U, (uint8_t)51U,
  (uint8_t)191U, (uint8_t)162U, (uint8_t)72U,  (uint8_t)219U, (uint8_t)143U,
  (uint8_t)204U, (uint8_t)211U, (uint8_t)86U,  (uint8_t)93U,  (uint8_t)233U,
  (uint8_t)75U,  (uint8_t)191U, (uint8_t)177U, (uint8_t)47U,  (uint8_t)60U,
  (uint8_t)89U,  (uint8_t)255U, (uint8_t)70U,  (uint8_t)194U, (uint8_t)113U,
  (uint8_t)191U, (uint8_t)131U
};

uint8_t nonce[32U] = {
  (uint8_t)148U, (uint8_t)161U, (uint8_t)187U, (uint8_t)177U, (uint8_t)75U,
  (uint8_t)144U, (uint8_t)106U, (uint8_t)97U,  (uint8_t)162U, (uint8_t)128U,
  (uint8_t)242U, (uint8_t)69U,  (uint8_t)249U, (uint8_t)233U, (uint8_t)60U,
  (uint8_t)127U, (uint8_t)59U,  (uint8_t)74U,  (uint8_t)98U,  (uint8_t)71U,
  (uint8_t)130U, (uint8_t)79U,  (uint8_t)93U,  (uint8_t)51U,  (uint8_t)185U,
  (uint8_t)103U, (uint8_t)7U,   (uint8_t)135U, (uint8_t)100U, (uint8_t)42U,
  (uint8_t)104U, (uint8_t)222U
};

uint8_t siggen_vectors_low5[32U] = {
  (uint8_t)243U, (uint8_t)172U, (uint8_t)128U, (uint8_t)97U,  (uint8_t)181U,
  (uint8_t)20U,  (uint8_t)121U, (uint8_t)91U,  (uint8_t)136U, (uint8_t)67U,
  (uint8_t)227U, (uint8_t)214U, (uint8_t)98U,  (uint8_t)149U, (uint8_t)39U,
  (uint8_t)237U, (uint8_t)42U,  (uint8_t)253U, (uint8_t)107U, (uint8_t)31U,
  (uint8_t)106U, (uint8_t)85U,  (uint8_t)90U,  (uint8_t)122U, (uint8_t)202U,
  (uint8_t)187U, (uint8_t)94U,  (uint8_t)111U, (uint8_t)121U, (uint8_t)200U,
  (uint8_t)194U, (uint8_t)172U
};

uint8_t siggen_vectors_low6[32U] = { 0xcf, 0xa7, 0x40, 0xfe, 0xc7, 0x67, 0x96,
                                     0xd2, 0xe3, 0x92, 0x16, 0xbe, 0x7e, 0xbf,
                                     0x58, 0x0e, 0xa3, 0xc0, 0xef, 0x4b, 0xb0,
                                     0x0a, 0xb2, 0xe7, 0xe4, 0x20, 0x84, 0x34,
                                     0xf4, 0x5f, 0x8c, 0x9c };

static uint8_t px0_0[32] = { 0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c,
                             0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
                             0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4,
                             0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87

};
static uint8_t py0_0[32] = { 0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06,
                             0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
                             0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0,
                             0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac };

static uint8_t scalar0[32] = { 0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda,
                               0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
                               0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e,
                               0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34

};

bool
testImplementationHacl()
{
  uint8_t* result = (uint8_t*)malloc(sizeof(uint8_t) * 64);
  bool flag =
    Hacl_P256_ecdsa_sign_p256_without_hash(result, 32, digest, prKey, nonce);
  bool s0 = compare_and_print(32, result, siggen_vectors_low5);
  bool s1 = compare_and_print(32, result + 32, siggen_vectors_low6);
  return s0 && s1 && flag;
}

TEST(P256Test, BasicTest)
{
  EXPECT_TRUE(testImplementationHacl());
}

//=== Wycheproof tests ====

#define bytes std::vector<uint8_t>

typedef struct
{
  bytes public_key;
  bytes msg;
  bytes sig;
  bool valid;
} TestCase;

std::vector<TestCase>
read_json()
{

  // Read JSON test vector
  std::string test_dir = "ecdsa_secp256r1_sha256_test.json";
  std::ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();

    // Read the key
    auto key = test_value["key"];
    auto public_key = from_hex(key["uncompressed"]);

    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto msg = from_hex(test_case_value["msg"]);
      auto sig = from_hex(test_case_value["sig"]);
      auto result = test_case_value["result"];
      bool valid = result == "valid" || result == "acceptable";

      tests_out.push_back({ public_key, msg, sig, valid });
    }
  }

  return tests_out;
}

class P256EcdsaWycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(P256EcdsaWycheproof, TryWycheproof)
{
  const TestCase& test_case(GetParam());

  // Stupid const
  uint8_t* public_key = const_cast<uint8_t*>(test_case.public_key.data());
  uint8_t* msg = const_cast<uint8_t*>(test_case.msg.data());

  // Convert public key first
  uint8_t plain_public_key[64] = { 0 };
  bool uncompressed_point = false;
  bool compressed_point = false;
  if (test_case.public_key.size() >= 65) {
    uncompressed_point =
      Hacl_P256_uncompressed_to_raw(public_key, plain_public_key);
  }
  if (!uncompressed_point && test_case.public_key.size() >= 32) {
    compressed_point =
      Hacl_P256_compressed_to_raw(public_key, plain_public_key);
  }
  EXPECT_TRUE(uncompressed_point || compressed_point || !test_case.valid);

  // Parse DER signature.
  // FIXME: This should really be in the HACL* libraray.
  //        The parsing here is opportunistic and not robust.
  size_t sig_pointer = 0;
  if (test_case.valid) {
    EXPECT_TRUE(test_case.sig.size() >= 2);
  }
  bytes r, s;

  if (test_case.sig.size() > 2) {
    if (test_case.valid) {
      size_t pos = 0;
      EXPECT_EQ(test_case.sig[pos++], 0x30); // Sequence tag
      auto der_length = test_case.sig[pos++];
      EXPECT_FALSE(der_length & 0x80);
      EXPECT_EQ(test_case.sig[pos++], 0x02); // Integer
      auto x_length = test_case.sig[pos++];
      r = bytes(&test_case.sig[pos], &test_case.sig[pos] + x_length);
      pos += x_length;
      EXPECT_EQ(test_case.sig[pos++], 0x02); // Integer
      auto y_length = test_case.sig[pos++];
      s = bytes(&test_case.sig[pos], &test_case.sig[pos] + y_length);
      pos += y_length;
      EXPECT_EQ(pos, der_length + 2);
    }
  }
  if (r.size() != 0 && s.size() != 0) {
    // Removing leading 0s and make r and s 32 bytes each
    while (r[0] == 0x00) {
      r.erase(r.begin());
    }
    while (r.size() < 32) {
      r.insert(r.begin(), 0);
    }
    while (s[0] == 0x00) {
      s.erase(s.begin());
    }
    while (s.size() < 32) {
      s.insert(s.begin(), 0);
    }
    EXPECT_EQ(32, r.size());
    EXPECT_EQ(32, s.size());

    // Due to https://github.com/project-everest/hacl-star/issues/327
    // we fake the msg pointer here for now if it's NULL.
    if (!msg) {
      msg = r.data(); // the length is 0 so we never do anything with this.
      EXPECT_EQ(0, test_case.msg.size());
    }
    EXPECT_EQ(
      test_case.valid,
      Hacl_P256_ecdsa_verif_p256_sha2(
        test_case.msg.size(), msg, plain_public_key, r.data(), s.data()));
  }
}

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         P256EcdsaWycheproof,
                         ::testing::ValuesIn(read_json()));
