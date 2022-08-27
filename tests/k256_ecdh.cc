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

#include "Hacl_EC_K256.h"
#include "util.h"

using json = nlohmann::json;
using namespace std;

// See
// https://github.com/google/wycheproof/blob/master/schemas/ecdh_test_schema.json
class WycheproofEcdh
{
public:
  uint32_t tcId;
  bytes public_key_asn1;
  bytes private_key;
  bytes shared;
  bool valid;
  bool AddSubChain;
  bool CompressedPoint;
  bool InvalidAsn;
  bool InvalidPublic;
  bool ModifiedPrime;
  bool UnnamedCurve;
  bool UnusedParam;
  bool WeakPublicKey;
  bool WrongOrder;
};

ostream&
operator<<(ostream& os, const WycheproofEcdh& test)
{
  os << "WycheproofEcdh {" << endl
     << "\t.tcId = " << test.tcId << endl
     << "\t.public_key_asn1 = " << bytes_to_hex(test.public_key_asn1) << endl
     << "\t.private_key = " << bytes_to_hex(test.private_key) << endl
     << "\t.shared = " << bytes_to_hex(test.shared) << endl
     << "\t.valid = " << test.valid << endl
     << "\t.AddSubChain = " << test.AddSubChain << endl
     << "\t.CompressedPoint = " << test.CompressedPoint << endl
     << "\t.InvalidAsn = " << test.InvalidAsn << endl
     << "\t.InvalidPublic = " << test.InvalidPublic << endl
     << "\t.ModifiedPrime = " << test.ModifiedPrime << endl
     << "\t.UnnamedCurve = " << test.UnnamedCurve << endl
     << "\t.UnusedParam = " << test.UnusedParam << endl
     << "\t.WeakPublicKey = " << test.WeakPublicKey << endl
     << "\t.WrongOrder = " << test.WrongOrder << endl
     << "}" << endl;
  return os;
}

vector<WycheproofEcdh>
read_wycheproof_ecdh(string path)
{
  ifstream json_test_file(path);
  json tests_raw;
  json_test_file >> tests_raw;

  vector<WycheproofEcdh> tests_out;

  // Read test group
  for (auto& group_raw : tests_raw["testGroups"].items()) {
    auto group = group_raw.value();

    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();

      uint32_t tcId = test["tcId"];
      auto public_key_asn1 = from_hex(test["public"]);
      auto private_key = from_hex(test["private"]);
      auto shared = from_hex(test["shared"]);
      auto result = test["result"];
      bool valid = result == "valid" || result == "acceptable";

      bool AddSubChain = false;
      bool CompressedPoint = false;
      bool InvalidAsn = false;
      bool InvalidPublic = false;
      bool ModifiedPrime = false;
      bool UnnamedCurve = false;
      bool UnusedParam = false;
      bool WeakPublicKey = false;
      bool WrongOrder = false;

      for (auto flag_raw : test["flags"].items()) {
        string flag = flag_raw.value();

        if (flag == "AddSubChain") {
          AddSubChain = true;
        }
        if (flag == "CompressedPoint") {
          CompressedPoint = true;
        }
        if (flag == "InvalidAsn") {
          InvalidAsn = true;
        }
        if (flag == "InvalidPublic") {
          InvalidPublic = true;
        }
        if (flag == "ModifiedPrime") {
          ModifiedPrime = true;
        }
        if (flag == "UnnamedCurve") {
          UnnamedCurve = true;
        }
        if (flag == "UnusedParam") {
          UnusedParam = true;
        }
        if (flag == "WeakPublicKey") {
          WeakPublicKey = true;
        }
        if (flag == "WrongOrder") {
          WrongOrder = true;
        }
      }

      tests_out.push_back({ tcId,
                            public_key_asn1,
                            private_key,
                            shared,
                            valid,
                            AddSubChain,
                            CompressedPoint,
                            InvalidAsn,
                            InvalidPublic,
                            ModifiedPrime,
                            UnnamedCurve,
                            UnusedParam,
                            WeakPublicKey,
                            WrongOrder

      });
    }
  }

  return tests_out;
}

class K256EcdhWycheproof : public ::testing::TestWithParam<WycheproofEcdh>
{};

TEST_P(K256EcdhWycheproof, KAT)
{
  WycheproofEcdh test = GetParam();

  // Obtain public key from test.
  vector<uint64_t> public_key(15);
  {
    if (test.CompressedPoint) {
      // Instead of parsing ASN.1, we just ignore the prefix ...
      bytes prefix = from_hex("3056301006072a8648ce3d020106052b8104000a034200");
      bytes compressed(test.public_key_asn1.begin() + prefix.size(),
                       test.public_key_asn1.end());

      bool res =
        Hacl_EC_K256_point_decompress(compressed.data(), public_key.data());

      if (test.valid) {
        EXPECT_TRUE(res);
      } else {
        return;
      }
    } else {
      // TODO(https://github.com/cryspen/hacl-packages/issues/157)
      cout << "Skipping. Only compressed points are supported for now." << endl;
      return;
    }
  }

  // Obtain private key from test:
  bytes private_key;
  {
    if (test.private_key.size() == 32) {
      private_key = bytes(test.private_key.begin(), test.private_key.end());
    } else if (test.private_key.size() == 33) {
      private_key = bytes(test.private_key.begin() + 1, test.private_key.end());
    } else {
      cout << "Unsupported private key size." << endl;
      return;
    }
  }

  // Compute shared secret.
  vector<uint64_t> shared_projective(15);
  Hacl_EC_K256_point_mul(
    private_key.data(), public_key.data(), shared_projective.data());

  // Obtain raw serialized x-coordinate.
  bytes shared_compressed(33);
  Hacl_EC_K256_point_compress(shared_projective.data(),
                              shared_compressed.data());

  // Trim first byte.
  ASSERT_EQ(shared_compressed[0], 0x02);
  bytes shared = bytes(shared_compressed.begin() + 1, shared_compressed.end());

  if (test.valid) {
    EXPECT_EQ(shared, test.shared);
  } else {
    EXPECT_NE(shared, test.shared);
  }
}

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  K256EcdhWycheproof,
  ::testing::ValuesIn(read_wycheproof_ecdh("ecdh_secp256k1_test.json")));
