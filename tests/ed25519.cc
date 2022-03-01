/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <fstream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "util.h"

#include "Hacl_Ed25519.h"

using json = nlohmann::json;

// TODO: Use TEST_P, see chachapoly test for example
TEST(Ed25519Test, WycheproofTest)
{
  // Read JSON test vector
  std::string test_dir = "eddsa_test.json";
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
        EXPECT_TRUE(result == "invalid");
        continue;
      }
      if (sig.length() > 128) {
        EXPECT_TRUE(result == "invalid");
        continue;
      }
      if (sig.length() < 128) {
        EXPECT_TRUE(result == "invalid");
        continue;
      }

      // First sign and check that the signature is correct.
      auto signature_bytes = from_hex(sig);
      uint8_t my_signature[64] = { 0 };
      Hacl_Ed25519_sign(&my_signature[0],
                        from_hex(sk).data(),
                        msg_bytes.size(),
                        msg_bytes.data());
      std::vector<uint8_t> my_signature_vector(my_signature, my_signature + 64);
      if (result == "valid") {
        EXPECT_EQ(my_signature_vector, signature_bytes)
          << "Got: " << bytes_to_hex(my_signature_vector) << std::endl
          << "Expected: " << sig << std::endl;

        bool self_test = Hacl_Ed25519_verify(from_hex(pk).data(),
                                             msg_bytes.size(),
                                             msg_bytes.data(),
                                             &my_signature[0]);
        EXPECT_TRUE(self_test);
      } else {
        EXPECT_NE(my_signature_vector, signature_bytes)
          << "Got: " << bytes_to_hex(my_signature_vector) << std::endl
          << "Unexpected: " << sig << std::endl;
      }

      // Now verify the signature from the KAT.
      bool valid = Hacl_Ed25519_verify(from_hex(pk).data(),
                                       msg_bytes.size(),
                                       msg_bytes.data(),
                                       signature_bytes.data());
      if (result == "valid") {
        EXPECT_TRUE(valid);
      } else {
        EXPECT_FALSE(valid)
          << "HACL result: "
          << "sign(" << msg << ") := " << sig << " is " << result << std::endl;
      }
    }
  }
}
