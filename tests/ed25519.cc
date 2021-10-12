#include <fstream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "util.h"

#include "Hacl_Ed25519.h"

using json = nlohmann::json;

TEST(Ed25519Test, WycheprofTest)
{
  // Read JSON test vector
  std::string test_dir = TEST_DIR;
  test_dir += "/eddsa_test.json";
  std::ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();
    auto pk = test_value["key"]["pk"];
    auto sk = test_value["key"]["sk"];

    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto msg = test_case_value["msg"];
      std::string sig = test_case_value["sig"];
      auto result = test_case_value["result"];

      auto msg_bytes = from_hex(msg);
      // XXX: HACL can't handle invalid lengths ...
      if (sig.length() == 0) {
        continue;
      }
      if (sig.length() > 128) {
        // std::cout << "sig length: " << sig.length() << std::endl;
        // std::cout << "sign(" << msg << ") := " << sig << " is " << result <<
        // "\n";
        continue;
      }
      bool valid = Hacl_Ed25519_verify(from_hex(pk).data(),
                                       msg_bytes.size(),
                                       msg_bytes.data(),
                                       from_hex(sig).data());
      if (result == "valid") {
        EXPECT_TRUE(valid);
      } else {
        // FIXME: Failing on a case
        EXPECT_FALSE(valid)
          << "HACL result: "
          << "sign(" << msg << ") := " << sig << " is " << result << std::endl;
      }
    }
  }
}
