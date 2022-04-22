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

#include "EverCrypt_Ed25519.h"
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
      uint8_t evercrypt_signature[64] = { 0 };
      Hacl_Ed25519_sign(&my_signature[0],
                        from_hex(sk).data(),
                        msg_bytes.size(),
                        msg_bytes.data());
      EverCrypt_Ed25519_sign(&evercrypt_signature[0],
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

        self_test = EverCrypt_Ed25519_verify(from_hex(pk).data(),
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
      bool valid_evercrypt = EverCrypt_Ed25519_verify(from_hex(pk).data(),
                                                      msg_bytes.size(),
                                                      msg_bytes.data(),
                                                      signature_bytes.data());
      if (result == "valid") {
        EXPECT_TRUE(valid);
        EXPECT_TRUE(valid_evercrypt);
      } else {
        EXPECT_FALSE(valid | valid_evercrypt)
          << "HACL result: "
          << "sign(" << msg << ") := " << sig << " is " << result << std::endl;
      }
    }
  }
}
