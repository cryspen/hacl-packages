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

#include "EverCrypt_Ed25519.h"
#include "Hacl_Ed25519.h"
#include "evercrypt.h"
#include "util.h"

using namespace std;
using json = nlohmann::json;

// See
// https://github.com/google/wycheproof/blob/master/schemas/eddsa_verify_schema.json.
class WycheproofEdDsaVerify
{
public:
  bytes sk;
  bytes pk;
  bytes msg;
  bytes sig;
  bool valid;
};

ostream&
operator<<(ostream& os, const WycheproofEdDsaVerify& test)
{
  os << "WycheproofEdDsaVerify {" << endl
     << "\t.sk = " << bytes_to_hex(test.sk) << "," << endl
     << "\t.pk = " << bytes_to_hex(test.pk) << "," << endl
     << "\t.msg = " << bytes_to_hex(test.msg) << "," << endl
     << "\t.sig = " << bytes_to_hex(test.sig) << "," << endl
     << "\t.valid = " << test.valid << "," << endl
     << "}" << endl;
  return os;
}

vector<WycheproofEdDsaVerify>
read_wycheproof_eddsa_verify(string path)
{
  ifstream json_test_file(path);
  json tests_raw;
  json_test_file >> tests_raw;

  vector<WycheproofEdDsaVerify> tests;

  for (auto& group_raw : tests_raw["testGroups"].items()) {
    auto group = group_raw.value();

    auto sk = from_hex(group["key"]["sk"]);
    auto pk = from_hex(group["key"]["pk"]);

    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();

      bytes msg = from_hex(test["msg"]);
      bytes sig = from_hex(test["sig"]);

      bool valid;
      if (test["result"] == "valid") {
        valid = true;
      } else if (test["result"] == "invalid") {
        valid = false;
      } else {
        throw "Unexpected value.";
      }

      // XXX: HACL can't handle invalid lengths ...
      if (sig.size() != 64) {
        EXPECT_FALSE(valid);
        continue;
      }

      tests.push_back(WycheproofEdDsaVerify{
        .sk = sk,
        .pk = pk,
        .msg = msg,
        .sig = sig,
        .valid = valid,
      });
    }
  }

  return tests;
}

// -----------------------------------------------------------------------------

class Ed25519Suite : public ::testing::TestWithParam<WycheproofEdDsaVerify>
{};

TEST_P(Ed25519Suite, Wycheproof)
{
  auto test = GetParam();

  // Sign and check that the signature is correct.
  bytes my_signature(64);
  Hacl_Ed25519_sign(
    my_signature.data(), test.sk.data(), test.msg.size(), test.msg.data());

  if (test.valid) {
    EXPECT_EQ(my_signature, test.sig)
      << "Got: " << bytes_to_hex(my_signature) << endl
      << "Expected: " << bytes_to_hex(test.sig) << endl;
  } else {
    EXPECT_NE(my_signature, test.sig)
      << "Got: " << bytes_to_hex(my_signature) << endl
      << "Unexpected: " << bytes_to_hex(test.sig) << endl;
  }

  // Verify the signature from the KAT.
  bool got_valid = Hacl_Ed25519_verify(
    test.pk.data(), test.msg.size(), test.msg.data(), test.sig.data());

  ASSERT_EQ(test.valid, got_valid);
}

// ----- EverCrypt -------------------------------------------------------------

typedef EverCryptSuite<string> Ed25519EverCryptDummySuite;

TEST_P(Ed25519EverCryptDummySuite, SecretToPublic)
{
  vector<tuple<bytes, bytes>> tests = {
    make_tuple(
      from_hex(
        "53b94cbed7c63839112f544f910227c31162d6c0701b790283219eba9247560a"),
      from_hex(
        "b558fcb632dfea2c2311092ea430769144f5358e9ee0649d704a93b53fc620e1")),
    make_tuple(
      from_hex(
        "02df5d9279309cce5f34634ddd920ecbbe6fd2d3a698df42ccd1071dd0056df7"),
      from_hex(
        "4a785ac25c4afc9cfcc4198a4fe031f91598745ed7d435be307f739842a6ea35")),
    make_tuple(
      from_hex(
        "d7007894e12a3e053ffe8277cb2efecff8e874ad1fec8a4d75fb722d90ca1137"),
      from_hex(
        "7d615b7609b49ddac5d96241bf992e2da49397af67f595a6ef6f3891a59904e2")),
    make_tuple(
      from_hex(
        "37854dc9703c61f66c46acedab6af45a92bdb267b781f81a066a689c56765868"),
      from_hex(
        "5b2cc21bd233d5df8ef5fc35f1de5072f002f492b2aa1f0abdf3de6ea5f81cb0")),
    make_tuple(
      from_hex(
        "8f23cd3a38a6894a85f114c5684a7f3bbdc587264dcd5351c987211c73cf7b7c"),
      from_hex(
        "ca38f978957b53d86cdd3d704cb1615e21f0f4b4350475f2ac442207966c2c01")),
    make_tuple(
      from_hex(
        "d12509006cdea3ec6cb0bcdd37d333d5d268ead6ef3c2bd464a30352e5ed9c4e"),
      from_hex(
        "a3b00a0373a096e42f8f742bd154ce54a2c38d7e37bbb9687ae8b49cb0851170")),
    make_tuple(
      from_hex(
        "73d139edeff42e62e1a1aaf4c5b2563fc8f6f8fdafb8219ceb7d1d31a9567ee3"),
      from_hex(
        "169215bdc6496400661d570331b2c88c1f6b71b782e81a3859f6e79246870a2d")),
    make_tuple(
      from_hex(
        "580f50dba34706dcaf7aeb6df3ec91125d710beeb3159183ee0d44a96ee4a094"),
      from_hex(
        "f864369759fef50610a0bd6cbae899421620ddb7194a56822b7e4ff02bfb3544")),
    make_tuple(
      from_hex(
        "c46ec4df3754dd18128f623b88acac661736096b03c4dc2f4deeb33b11b351c8"),
      from_hex(
        "484f109a9a5b24610e1c80119e0862e90f8187fa64e3e33ce1ddff61dc485f97")),
    make_tuple(
      from_hex(
        "1f7de319b443dbb8d78d02d87957a328f3b07a8b109d795ebf2ca061f0e62403"),
      from_hex(
        "200137ba771adc3fcb823bd25bd518e2d8f2a141fd2c6765670986c3c2d89a6d")),
    make_tuple(
      from_hex(
        "f3017d35464e5a9246bdd1801f062bb3d52a6c24c055453f679c4e3169c02af5"),
      from_hex(
        "25fbb10343ed344bebed27d5a1539163ef13f461798928be59259a5c9b362799")),
    make_tuple(
      from_hex(
        "1dfc2e02faed3f8646b7ebdf2f2dae4703bd7e08727865d2f7eb0191c320f0a0"),
      from_hex(
        "4b16be9f0dae20e1533688011758ba36f373d57771b3e2d3ebfaa9bf058924d2")),
    make_tuple(
      from_hex(
        "66d2b7c7c483cc5350670791d5fd54a000b29e494d6852f5f868246531172483"),
      from_hex(
        "17aa0b16152a228a2c277a8a319e73d5316294e9006bb76ebaa88561029b4a27")),
    make_tuple(
      from_hex(
        "8a6e6b79f1cc1f6bb21014f44857c3a417e54eab5064b4dc238a49f55925f11b"),
      from_hex(
        "dce4960551d7dd9d740606be0c3f164f3ae77308800080460f7cf5fb4723cc3c")),
    make_tuple(
      from_hex(
        "f6189eb63ca9647eb4333eb51ce116b62350e18a28da9e5290172de6a62390ad"),
      from_hex(
        "966d2b15ff1493c7d590aaefddc55ba269efdbc12a45392b9889edc960526d1d")),
    make_tuple(
      from_hex(
        "a80272a07af7fc9296b534763f69a4d1a6af1a6b84a2586e9eba76b235db3855"),
      from_hex(
        "a29da676e0d6f13989f67a7497069ba5ae73e266fb4a2814574978840cefaa90")),
  };

  for (auto test : tests) {
    bytes sk;
    bytes pk;
    tie(sk, pk) = test;

    bytes got_pk(pk.size());
    EverCrypt_Ed25519_secret_to_public(got_pk.data(), sk.data());
    ASSERT_EQ(pk, got_pk);
  }
}

typedef EverCryptSuite<WycheproofEdDsaVerify> Ed25519EverCryptSuite;

TEST_P(Ed25519EverCryptSuite, Wycheproof)
{
  EverCryptConfig config;
  WycheproofEdDsaVerify test;
  tie(config, test) = this->GetParam();

  // Sign and check that the signature is correct.
  bytes my_signature(64);
  EverCrypt_Ed25519_sign(
    my_signature.data(), test.sk.data(), test.msg.size(), test.msg.data());

  if (test.valid) {
    EXPECT_EQ(my_signature, test.sig)
      << "Got: " << bytes_to_hex(my_signature) << endl
      << "Expected: " << bytes_to_hex(test.sig) << endl;
  } else {
    EXPECT_NE(my_signature, test.sig)
      << "Got: " << bytes_to_hex(my_signature) << endl
      << "Unexpected: " << bytes_to_hex(test.sig) << endl;
  }

  // Verify the signature from the KAT.
  bool got_valid = EverCrypt_Ed25519_verify(
    test.pk.data(), test.msg.size(), test.msg.data(), test.sig.data());

  ASSERT_EQ(test.valid, got_valid);
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  Ed25519Suite,
  ::testing::ValuesIn(read_wycheproof_eddsa_verify("eddsa_test.json")));

// ----- EverCrypt -------------------------------------------------------------

vector<EverCryptConfig>
generate_eddsa_configs()
{
  vector<EverCryptConfig> configs;

  configs.push_back(EverCryptConfig{
    .disable_adx = false,
    .disable_aesni = false,
    .disable_avx = false,
    .disable_avx2 = false,
    .disable_avx512 = false,
    .disable_bmi2 = false,
    .disable_movbe = false,
    .disable_pclmulqdq = false,
    .disable_rdrand = false,
    .disable_shaext = false,
    .disable_sse = false,
  });

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  Ed25519EverCryptDummySuite,
  ::testing::Combine(::testing::ValuesIn(generate_eddsa_configs()),
                     ::testing::Values("")));

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  Ed25519EverCryptSuite,
  ::testing::Combine(
    ::testing::ValuesIn(generate_eddsa_configs()),
    ::testing::ValuesIn(read_wycheproof_eddsa_verify("eddsa_test.json"))));
