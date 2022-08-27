#pragma once

#include <fstream>
#include <nlohmann/json.hpp>

#include "util.h"

using namespace std;
using json = nlohmann::json;

// Test case corresponding to Wycheproof's AEAD test schema ...
//   https://github.com/google/wycheproof/blob/master/schemas/aead_test_schema.json
class WycheproofAeadTest
{
public:
  uint32_t tcId;
  uint32_t keySize;
  bytes key;
  bytes iv;
  bytes aad;
  bytes msg;
  bytes ct;
  bytes tag;
  bool valid;
};

ostream&
operator<<(ostream& os, const WycheproofAeadTest& test)
{
  os << "WycheproofAeadTest {" << endl
     << "\t.tcId = " << test.tcId << endl
     << "\t.keySize = " << test.keySize << endl
     << "\t.key = " << bytes_to_hex(test.key) << endl
     << "\t.iv = " << bytes_to_hex(test.iv) << endl
     << "\t.aad = " << bytes_to_hex(test.aad) << endl
     << "\t.msg = " << bytes_to_hex(test.msg) << endl
     << "\t.ct = " << bytes_to_hex(test.ct) << endl
     << "\t.tag = " << bytes_to_hex(test.tag) << endl
     << "\t.valid = " << test.valid << endl
     << "}" << endl;
  return os;
}

vector<WycheproofAeadTest>
read_wycheproof_aead_json(string path)
{
  ifstream json_test_file(path);
  json test_vectors;
  json_test_file >> test_vectors;

  vector<WycheproofAeadTest> tests_out;

  for (auto& group_raw : test_vectors["testGroups"].items()) {
    auto group = group_raw.value();

    uint32_t keySize = group["keySize"];
    EXPECT_EQ(group["tagSize"], 128);

    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();

      uint32_t tcId = test["tcId"];
      auto msg = from_hex(test["msg"]);
      auto key = from_hex(test["key"]);
      auto iv = from_hex(test["iv"]);
      auto aad = from_hex(test["aad"]);
      auto ct = from_hex(test["ct"]);
      auto tag = from_hex(test["tag"]);
      auto result = test["result"];
      bool valid = result == "valid";

      if (iv.size() != 12) {
        cout << "Skipping iv != 12." << endl;
        continue;
      }

      tests_out.push_back(WycheproofAeadTest{
        .tcId = tcId,
        .keySize = keySize,
        .key = key,
        .iv = iv,
        .aad = aad,
        .msg = msg,
        .ct = ct,
        .tag = tag,
        .valid = valid,
      });
    }
  }

  return tests_out;
}
