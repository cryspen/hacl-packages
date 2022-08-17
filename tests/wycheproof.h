#pragma once

#include <fstream>
#include <nlohmann/json.hpp>

#include "util.h"

using namespace std;
using json = nlohmann::json;

class WycheproofChacha20Poly1305
{
public:
  bytes msg;
  bytes key;
  bytes iv;
  bytes aad;
  bytes ct;
  bytes tag;
  bool valid;
};

ostream&
operator<<(ostream& os, const WycheproofChacha20Poly1305& test)
{
  os << "WycheproofChacha20Poly1305 {" << endl
     << "\t.msg = " << bytes_to_hex(test.msg) << endl
     << "\t.key = " << bytes_to_hex(test.key) << endl
     << "\t.iv = " << bytes_to_hex(test.iv) << endl
     << "\t.aad = " << bytes_to_hex(test.aad) << endl
     << "\t.ct = " << bytes_to_hex(test.ct) << endl
     << "\t.tag = " << bytes_to_hex(test.tag) << endl
     << "\t.valid = " << test.valid << endl
     << "}" << endl;
  return os;
}

vector<WycheproofChacha20Poly1305>
read_wycheproof_chacha20_poly1305_json(string path)
{
  string test_dir = path;
  ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  vector<WycheproofChacha20Poly1305> tests_out;

  // Read test group
  for (auto& group_raw : test_vectors["testGroups"].items()) {
    auto group = group_raw.value();

    // HACL only support 12 byte IVs.
    if (group["ivSize"] != 96) {
      continue;
    }

    EXPECT_EQ(group["keySize"], 256);
    EXPECT_EQ(group["tagSize"], 128);

    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();

      auto msg = from_hex(test["msg"]);
      auto key = from_hex(test["key"]);
      auto iv = from_hex(test["iv"]);
      auto aad = from_hex(test["aad"]);
      auto ct = from_hex(test["ct"]);
      auto tag = from_hex(test["tag"]);
      auto result = test["result"];
      bool valid = result == "valid";

      tests_out.push_back(
        WycheproofChacha20Poly1305{ msg, key, iv, aad, ct, tag, valid });
    }
  }

  return tests_out;
}
