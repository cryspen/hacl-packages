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
  bytes public_key(64);
  {
    // Instead of parsing ASN.1, we just ignore the prefix ...
    bytes prefix = from_hex("3056301006072a8648ce3d020106052b8104000a034200");
    bytes pk = bytes(test.public_key_asn1.begin() + prefix.size(), test.public_key_asn1.end());
    if (test.CompressedPoint) {
      Hacl_K256_ECDSA_public_key_compressed_to_raw(public_key.data(), pk.data());
    } else {
      Hacl_K256_ECDSA_public_key_uncompressed_to_raw(public_key.data(), pk.data());
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
  bytes shared(64);
  bool res = Hacl_K256_ECDSA_ecdh(shared.data(), public_key.data(), private_key.data());

  if (test.valid) {
    EXPECT_TRUE(res);
    EXPECT_EQ(bytes(shared.begin(), shared.begin() + 32), test.shared);
  } else {
    EXPECT_FALSE(res);
    EXPECT_NE(bytes(shared.begin(), shared.begin() + 32), test.shared);
  }
}

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  K256EcdhWycheproof,
  ::testing::ValuesIn(read_wycheproof_ecdh("ecdh_secp256k1_test.json")));
