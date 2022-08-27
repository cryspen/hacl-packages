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

#include "Hacl_Hash_Base.h"
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
sign(bytes e,
     bytes d,
     bytes n,
     bytes salt,
     Spec_Hash_Definitions_hash_alg alg,
     bytes msg,
     bytes& sgnt,
     bool* out);

void
verify(bytes e,
       bytes n,
       uint32_t saltLen,
       Spec_Hash_Definitions_hash_alg alg,
       bytes msg,
       bytes sgnt,
       bool* out);

// -----------------------------------------------------------------------------

class RsaPssSignSuite : public ::testing::Test
{};

void
sign(bytes e,
     bytes d,
     bytes n,
     bytes salt,
     Spec_Hash_Definitions_hash_alg alg,
     bytes msg,
     bytes& sgnt,
     bool* out)
{
  uint64_t* skey = Hacl_RSAPSS_new_rsapss_load_skey(
    n.size() * 8, e.size() * 8, d.size() * 8, n.data(), e.data(), d.data());

  bytes sgnt_twin(n.size());

  bool got_twin = Hacl_RSAPSS_rsapss_sign(alg,
                                          n.size() * 8,
                                          e.size() * 8,
                                          d.size() * 8,
                                          skey,
                                          salt.size(),
                                          salt.data(),
                                          msg.size(),
                                          msg.data(),
                                          sgnt_twin.data());
  free(skey);

  bool got = Hacl_RSAPSS_rsapss_skey_sign(alg,
                                          n.size() * 8,
                                          e.size() * 8,
                                          d.size() * 8,
                                          n.data(),
                                          e.data(),
                                          d.data(),
                                          salt.size(),
                                          salt.data(),
                                          msg.size(),
                                          msg.data(),
                                          sgnt.data());

  ASSERT_EQ(got, got_twin) << "`Hacl_RSAPSS_rsapss_sign(...)` deviates from "
                              "`Hacl_RSAPSS_rsapss_skey_sign`.";
  ASSERT_EQ(sgnt, sgnt_twin) << "`Hacl_RSAPSS_rsapss_sign(...)` deviates from "
                                "`Hacl_RSAPSS_rsapss_skey_sign`.";

  *out = got;
}

TEST(RsaPssSignSuite, Group)
{
  bytes e = from_hex("010001");
  bytes d = from_hex(
    "12ddcf5652e462db7bd689e1604cf27dacb7435105880c8acac24ef9302c29bc819eaee139"
    "66d471114053e17d8ae3bca57460d1b177f8bd37bfbbee243cb5e3dde2ae34dff6b3095939"
    "c5c74d56a674a12b270d8213a6268ec3f332dd9cf746ba097b6ce8490be4dabfb83d02560e"
    "da766a3551681725230f31f7a67bc8f5e8968103426eac652a30893251431e434597c06487"
    "b05b49b7a6d2e4d263de4f7e7788471b19e8aa64f3dce41bf1f55f057d50187f95379a7f93"
    "09f6afa62ceca1e988df7c8dc484101349ca131fe9c4b4d42c63c788dc6e6ce93f11a0567c"
    "2830022c5ee73c1c55c668e2cdcc1fb88c91bfdd33e014c29cb8af2e84c14cf9f8ad");
  bytes n = from_hex(
    "bb6707ae65f4ee9e65ee1a1c08b431e556cd1000dc5358b97098c9546de8ef9b5a227cbd89"
    "fbca5fa1b0e7527cb4fd66d934f0edc166cf6f7944fb44997a0023885c319f25b7927b0c03"
    "74132f5ab38de2bfb25228ab4cf4c3932662d4af7dab73e2da520016b7df4d97575ffb90ff"
    "b0bda1b791f6e09cd70bc04bdc19b757279f271476fe774737ab816d0da86254a45cd98d5b"
    "ce77ccd950e1f16f572a4e45a292b501e6394e2e49cf547302222529cb754d3d255512fe83"
    "5874020d9f8662e22c000c8af6247be141bab2abf4a712ee1590d260bf3bb907a151604ec9"
    "354fc806f86eeaeb4df53dd822412189567fb5fc0bc2082a7c4f613834a72f985c27");

  std::vector<bytes> tests{
    from_hex(""),
    from_hex("00"),
    from_hex("aa"),
    from_hex("ff"),
    from_hex("0000000000000000"),
    from_hex("aaaaaaaaaaaaaaaa"),
    from_hex("ffffffffffffffff"),
    from_hex("000000000000000000"),
    from_hex("aaaaaaaaaaaaaaaaaa"),
    from_hex("ffffffffffffffffff"),
  };

  std::vector<Spec_Hash_Definitions_hash_alg> hashes{
    // TODO: #100
    Spec_Hash_Definitions_SHA2_256,
    Spec_Hash_Definitions_SHA2_384,
    Spec_Hash_Definitions_SHA2_512,
  };

  for (auto hash_alg : hashes) {
    uint32_t saltLen = Hacl_Hash_Definitions_hash_len(hash_alg);
    bytes salt(saltLen, 'A');

    bytes signature(n.size());

    for (auto test : tests) {
      bool got_sign;
      sign(e, d, n, salt, hash_alg, test, signature, &got_sign);

      bool got_verify;
      verify(e, n, salt.size(), hash_alg, test, signature, &got_verify);

      ASSERT_TRUE(got_verify);
    }
  }
}

// -----------------------------------------------------------------------------

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
  free(pkey);

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

  for (auto test : group.tests) {
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
      msg << "Expected first byte of \"n\" to be 0x00 in Wycheproof test (path="
          << path << ").";

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
        .tcId = tcId,
        .msg = msg,
        .sgnt = sgnt,
        .expected = expected,
      });
    }

    testGroups.push_back({
      .e = e,
      .n = n,
      .saltLen = saltLen,
      .a = a,
      .tests = tests,
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

// -----------------------------------------------------------------------------

TEST(BadSecretKey, RsaPssLoadKey)
{
  // (e, d, n)
  std::vector<std::tuple<bytes, bytes, bytes>> tests{
    { from_hex(""), from_hex(""), from_hex("") },
    { from_hex(""), from_hex("AA"), from_hex("") },
    { from_hex("AA"), from_hex(""), from_hex("") },
    { from_hex("AA"), from_hex("AA"), from_hex("") },
    { from_hex("AA"), from_hex("AA"), from_hex("AA") },
    { from_hex("AA"), from_hex("AAAA"), from_hex("AA") },
    { from_hex("AAAA"), from_hex("AA"), from_hex("AA") },
    { from_hex("AAAA"), from_hex("AAAA"), from_hex("AA") },
  };

  for (auto test : tests) {
    bytes e, d, n;
    std::tie(e, d, n) = test;

    uint64_t* skey = Hacl_RSAPSS_new_rsapss_load_skey(
      n.size() * 8, e.size() * 8, d.size() * 8, n.data(), e.data(), d.data());

    ASSERT_TRUE(skey == NULL);
  }
}

TEST(BadPublicKey, RsaPssLoadKey)
{
  // (e, n)
  std::vector<std::tuple<bytes, bytes>> tests{
    { from_hex(""), from_hex("") },
    { from_hex(""), from_hex("FF") },
    { from_hex("AA"), from_hex("") },
  };

  for (auto test : tests) {
    bytes e, n;
    std::tie(e, n) = test;

    uint64_t* pkey = Hacl_RSAPSS_new_rsapss_load_pkey(
      n.size() * 8, e.size() * 8, n.data(), e.data());

    ASSERT_TRUE(pkey == NULL);
  }
}
