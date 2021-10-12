#include <fstream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "util.h"

#include "Hacl_Chacha20Poly1305_32.h"
#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Chacha20Poly1305_128.h"
#endif
#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Chacha20Poly1305_256.h"
#endif

#include "chacha20poly1305_vectors.h"

using json = nlohmann::json;

// Function pointer to multiplex between the different implementations.
typedef void (*test_encrypt)(uint8_t*,
                             uint8_t*,
                             uint32_t,
                             uint8_t*,
                             uint32_t,
                             uint8_t*,
                             uint8_t*,
                             uint8_t*);
typedef uint32_t (*test_decrypt)(uint8_t*,
                                 uint8_t*,
                                 uint32_t,
                                 uint8_t*,
                                 uint32_t,
                                 uint8_t*,
                                 uint8_t*,
                                 uint8_t*);

bool
print_test(test_encrypt aead_encrypt,
           test_decrypt aead_decrypt,
           int in_len,
           uint8_t* in,
           uint8_t* key,
           uint8_t* nonce,
           int aad_len,
           uint8_t* aad,
           uint8_t* exp_mac,
           uint8_t* exp_cipher)
{
  uint8_t plaintext[in_len];
  memset(plaintext, 0, in_len * sizeof plaintext[0]);
  uint8_t ciphertext[in_len];
  memset(ciphertext, 0, in_len * sizeof ciphertext[0]);
  uint8_t mac[16] = { 0 };

  (*aead_encrypt)(key, nonce, aad_len, aad, in_len, in, ciphertext, mac);
  bool ok = print_result(in_len, ciphertext, exp_cipher);
  ok = ok && print_result(16, mac, exp_mac);

  int res = (*aead_decrypt)(
    key, nonce, aad_len, aad, in_len, plaintext, exp_cipher, exp_mac);
  ok = ok && (res == 0);
  ok = ok && print_result(in_len, plaintext, in);

  return ok;
}

class Chacha20Poly1305Testing
  : public ::testing::TestWithParam<chacha20poly1305_test_vector>
{};

TEST_P(Chacha20Poly1305Testing, TryTestVectors)
{
  const chacha20poly1305_test_vector& vectors(GetParam());
  bool test = print_test(&Hacl_Chacha20Poly1305_32_aead_encrypt,
                         &Hacl_Chacha20Poly1305_32_aead_decrypt,
                         vectors.input_len,
                         vectors.input,
                         &vectors.key[0],
                         &vectors.nonce[0],
                         vectors.aad_len,
                         vectors.aad,
                         &vectors.tag[0],
                         vectors.cipher);
  EXPECT_TRUE(test);

#ifdef HACL_CAN_COMPILE_VEC128
  test = print_test(&Hacl_Chacha20Poly1305_128_aead_encrypt,
                    &Hacl_Chacha20Poly1305_128_aead_decrypt,
                    vectors.input_len,
                    vectors.input,
                    &vectors.key[0],
                    &vectors.nonce[0],
                    vectors.aad_len,
                    vectors.aad,
                    &vectors.tag[0],
                    vectors.cipher);
  EXPECT_TRUE(test);
#endif // HACL_CAN_COMPILE_VEC128

#ifdef HACL_CAN_COMPILE_VEC256
  test = print_test(&Hacl_Chacha20Poly1305_256_aead_encrypt,
                    &Hacl_Chacha20Poly1305_256_aead_decrypt,
                    vectors.input_len,
                    vectors.input,
                    &vectors.key[0],
                    &vectors.nonce[0],
                    vectors.aad_len,
                    vectors.aad,
                    &vectors.tag[0],
                    vectors.cipher);
  EXPECT_TRUE(test);
#endif // HACL_CAN_COMPILE_VEC256
}

INSTANTIATE_TEST_SUITE_P(TestVectors,
                         Chacha20Poly1305Testing,
                         ::testing::ValuesIn(vectors));

TEST(Chacha20Poly1305Test, WycheproofTest)
{
  // Read JSON test vector
  std::string test_dir = TEST_DIR;
  test_dir += "/chacha20_poly1305_test.json";
  std::ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();
    if (test_value["ivSize"] != 96) {
      // HACL only support 12 byte IVs
      continue;
    }
    EXPECT_EQ(test_value["keySize"], 256);
    EXPECT_EQ(test_value["tagSize"], 128);

    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto msg = from_hex(test_case_value["msg"]);
      auto key = from_hex(test_case_value["key"]);
      auto iv = from_hex(test_case_value["iv"]);
      auto aad = from_hex(test_case_value["aad"]);
      auto ct = from_hex(test_case_value["ct"]);
      auto tag = from_hex(test_case_value["tag"]);
      auto result = test_case_value["result"];
      bool valid = result == "valid";

      auto msg_size = msg.size();
      uint8_t plaintext[msg_size];
      memset(plaintext, 0, msg_size * sizeof plaintext[0]);
      uint8_t ciphertext[msg_size];
      memset(ciphertext, 0, msg_size * sizeof ciphertext[0]);
      uint8_t mac[16] = { 0 };

      // Check that encryption yields the expected cipher text.
      Hacl_Chacha20Poly1305_32_aead_encrypt(key.data(),
                                            iv.data(),
                                            aad.size(),
                                            aad.data(),
                                            msg_size,
                                            msg.data(),
                                            ciphertext,
                                            mac);
      if (valid) {
        EXPECT_EQ(std::vector<uint8_t>(ciphertext, ciphertext + msg_size), ct);
        EXPECT_EQ(std::vector<uint8_t>(mac, mac + 16), tag);
      }

      int res = Hacl_Chacha20Poly1305_32_aead_decrypt(key.data(),
                                                      iv.data(),
                                                      aad.size(),
                                                      aad.data(),
                                                      msg_size,
                                                      plaintext,
                                                      ct.data(),
                                                      tag.data());
      EXPECT_EQ(res, valid ? 0 : 1);

// XXX: do less c&p
#ifdef HACL_CAN_COMPILE_VEC128
      // Check that encryption yields the expected cipher text.
      Hacl_Chacha20Poly1305_128_aead_encrypt(key.data(),
                                             iv.data(),
                                             aad.size(),
                                             aad.data(),
                                             msg_size,
                                             msg.data(),
                                             ciphertext,
                                             mac);
      if (valid) {
        EXPECT_EQ(std::vector<uint8_t>(ciphertext, ciphertext + msg_size), ct);
        EXPECT_EQ(std::vector<uint8_t>(mac, mac + 16), tag);
      }

      res = Hacl_Chacha20Poly1305_128_aead_decrypt(key.data(),
                                                   iv.data(),
                                                   aad.size(),
                                                   aad.data(),
                                                   msg_size,
                                                   plaintext,
                                                   ct.data(),
                                                   tag.data());
      EXPECT_EQ(res, valid ? 0 : 1);
#endif //  HACL_CAN_COMPILE_VEC128

// XXX: do less c&p
#ifdef HACL_CAN_COMPILE_VEC256
      // Check that encryption yields the expected cipher text.
      Hacl_Chacha20Poly1305_256_aead_encrypt(key.data(),
                                             iv.data(),
                                             aad.size(),
                                             aad.data(),
                                             msg_size,
                                             msg.data(),
                                             ciphertext,
                                             mac);
      if (valid) {
        EXPECT_EQ(std::vector<uint8_t>(ciphertext, ciphertext + msg_size), ct);
        EXPECT_EQ(std::vector<uint8_t>(mac, mac + 16), tag);
      }

      res = Hacl_Chacha20Poly1305_256_aead_decrypt(key.data(),
                                                   iv.data(),
                                                   aad.size(),
                                                   aad.data(),
                                                   msg_size,
                                                   plaintext,
                                                   ct.data(),
                                                   tag.data());
      EXPECT_EQ(res, valid ? 0 : 1);
#endif //  HACL_CAN_COMPILE_VEC256
    }
  }
}
