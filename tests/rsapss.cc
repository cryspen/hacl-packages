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

#include "Hacl_RSAPSS.h"
#include "Hacl_Spec.h"
#include "util.h"

using json = nlohmann::json;

typedef struct
{
  uint32_t tcId;
  bytes msg;
  bytes sgnt;
  bool expected;
} Test;

typedef struct
{
  bytes e;
  bytes n;
  uint32_t saltLen;
  Spec_Hash_Definitions_hash_alg a;
  std::vector<Test> tests;
} Group;

void
verify(bytes e,
       bytes n,
       uint32_t saltLen,
       Spec_Hash_Definitions_hash_alg alg,
       bytes msg,
       bytes sgnt,
       bool* out)
{
  uint64_t* pkey = Hacl_RSAPSS_new_rsapss_load_pkey(
    n.size() * 8, e.size() * 8, n.data(), e.data());

  bool got1 = Hacl_RSAPSS_rsapss_verify(alg,
                                        n.size() * 8,
                                        e.size() * 8,
                                        pkey,
                                        saltLen,
                                        sgnt.size(),
                                        sgnt.data(),
                                        msg.size(),
                                        msg.data());

  bool got2 = Hacl_RSAPSS_rsapss_pkey_verify(alg,
                                             n.size() * 8,
                                             e.size() * 8,
                                             n.data(),
                                             e.data(),
                                             saltLen,
                                             sgnt.size(),
                                             sgnt.data(),
                                             msg.size(),
                                             msg.data());

  ASSERT_EQ(got1, got2) << "`Hacl_RSAPSS_rsapss_verify(...)` deviates from "
                           "`Hacl_RSAPSS_rsapss_pkey_verify(...)`.";

  *out = got2;
}

class RsaPssVerifySuite : public ::testing::TestWithParam<Group>
{};

TEST_P(RsaPssVerifySuite, Group)
{
  auto group = GetParam();

  // std::cout << "e: " << bytes_to_hex(group.e) << std::endl
  //           << "n: " << bytes_to_hex(group.n) << std::endl;

  for (auto test : group.tests) {
    // std::cout << "msg: " << bytes_to_hex(test.msg) << std::endl
    //           << "sgnt: " << bytes_to_hex(test.sgnt) << std::endl;

    bool got;
    verify(group.e, group.n, group.saltLen, group.a, test.msg, test.sgnt, &got);

    EXPECT_EQ(test.expected, got) << "tcId=" << test.tcId;
  }
}

std::vector<Group>
read_json(char* path)
{
  json tests;
  std::ifstream file(path);
  file >> tests;

  std::vector<Group> testGroups;

  for (auto& group_raw : tests["testGroups"].items()) {
    auto group = group_raw.value();

    bytes e = from_hex(group["e"]);
    bytes n = from_hex(group["n"]);

    // Remove first 0x00 byte in n.
    if (n[0] == 0x00) {
      n.erase(n.begin());
    } else {
      std::ostringstream msg;
      msg << "Expected first byte of \"n\" to be 0x00 in Wycheproof test (path=" << path << ").";

      throw std::invalid_argument(msg.str());
    }

    uint32_t saltLen = group["sLen"];

    Spec_Hash_Definitions_hash_alg a;
    std::string sha = group["sha"];
    if (sha == "SHA-256") {
      a = Spec_Hash_Definitions_SHA2_256;
    } else if (sha == "SHA-512") {
      a = Spec_Hash_Definitions_SHA2_512;
    } else {
      std::ostringstream msg;
      msg << "Unexpected value \"" << sha
          << "\" in field \"sha\" (path=" << path << ").";

      throw std::invalid_argument(msg.str());
    }

    std::vector<Test> tests;
    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();
      uint32_t tcId = test["tcId"];

      auto msg = from_hex(test["msg"]);
      auto sgnt = from_hex(test["sig"]);

      bool expected;
      std::string result = test["result"];
      if (result == "valid" || result == "acceptable") {
        expected = true;
      } else if (result == "invalid") {
        expected = false;
      } else {
        std::ostringstream msg;
        msg << "Unexpected value \"" << result
            << "\" in field \"result\" (file=" << path << ", tcId=" << tcId
            << ").";

        throw std::invalid_argument(msg.str());
      }

      tests.push_back(Test{
        tcId : tcId,
        msg : msg,
        sgnt : sgnt,
        expected : expected,
      });
    }

    testGroups.push_back({
      e : e,
      n : n,
      saltLen : saltLen,
      a : a,
      tests : tests,
    });
  }

  return testGroups;
}

INSTANTIATE_TEST_SUITE_P(RsaPss2048Sha256Salt0,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_2048_sha256_mgf1_0_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss2048Sha256Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_2048_sha256_mgf1_32_test.json"))));

// INSTANTIATE_TEST_SUITE_P(RsaPss2048Sha512256Salt28,
//                          RsaPssVerifySuite,
//                          ::testing::ValuesIn(read_json(const_cast<char*>(
//                            "rsa_pss_2048_sha512_256_mgf1_28_test.json"))));
//
// INSTANTIATE_TEST_SUITE_P(RsaPss2048Sha512256Salt32,
//                         RsaPssVerifySuite,
//                         ::testing::ValuesIn(read_json(const_cast<char*>(
//                           "rsa_pss_2048_sha512_256_mgf1_32_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss3072Sha256Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_3072_sha256_mgf1_32_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss4096Sha256Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_4096_sha256_mgf1_32_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss4096Sha512Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_4096_sha512_mgf1_32_test.json"))));
