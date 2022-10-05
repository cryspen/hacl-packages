/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <gtest/gtest.h>

#include "Hacl_Chacha20Poly1305_32.h"
#include "Hacl_Chacha20_Vec32.h"
#include "chacha20poly1305_vectors.h"
#include "hacl-cpu-features.h"
#include "util.h"
#include "wycheproof.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Chacha20Poly1305_128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Chacha20Poly1305_256.h"
#endif

#define VALE                                                                   \
  TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64 ||                         \
    TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X86
#if VALE
// Only include this for checking CPU flags.
#include "Vale.h"
#endif

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
  uint8_t* plaintext = static_cast<uint8_t*>(malloc(in_len));
  memset(plaintext, 0, in_len * sizeof plaintext[0]);
  uint8_t* ciphertext = static_cast<uint8_t*>(malloc(in_len));
  memset(ciphertext, 0, in_len * sizeof ciphertext[0]);
  uint8_t mac[16] = { 0 };

  (*aead_encrypt)(key, nonce, aad_len, aad, in_len, in, ciphertext, mac);
  bool ok = compare_and_print(in_len, ciphertext, exp_cipher);
  ok = ok && compare_and_print(16, mac, exp_mac);

  int res = (*aead_decrypt)(
    key, nonce, aad_len, aad, in_len, plaintext, exp_cipher, exp_mac);
  ok = ok && (res == 0);
  ok = ok && compare_and_print(in_len, plaintext, in);

  free(plaintext);
  free(ciphertext);

  return ok;
}

// -----------------------------------------------------------------------------

TEST(ApiSuite, ApiTest)
{
  // Documentation.
  // Lines after START and before END are used in documentation.
  {
    // START OneShot
    // Note: This is only an example, and you must bring your own random.

    // Create a key ...
    uint8_t key[32];
    generate_random(key, 32);

    // ... and a nonce.
    uint8_t nonce[12];
    generate_random(nonce, 12);

    // We don't authenticate additional data in this example.
    const char* aad = "";
    const uint32_t aad_len = strlen(aad);

    // This is our message.
    const char* msg = "Hello, World!";
    const uint32_t msg_len = strlen(msg);

    // We need to allocate the same amount of memory for the ciphertext as for the plaintext ...
    uint8_t* cipher = (uint8_t*)malloc(msg_len);
    // ... and also need to provide additional memory for the mac.
    // Note that encyption and decryption can also be done in-place, i.e., cipher and plaintext can
    // point to the same memory.
    uint8_t mac[16];

    // Encryption.
    Hacl_Chacha20Poly1305_32_aead_encrypt(
      key, nonce, aad_len, (uint8_t*)aad, msg_len, (uint8_t*)msg, cipher, mac);

    // Decryption.
    // Allocate the same amount of memory for the recovered message as for the ciphertext.
    uint8_t* recovered = (uint8_t*)malloc(msg_len);

    uint32_t res = Hacl_Chacha20Poly1305_32_aead_decrypt(
      key, nonce, aad_len, (uint8_t*)aad, msg_len, (uint8_t*)recovered, cipher, mac);

    if (res == 0) {
      printf("Decryption successful.");
    }

    free(recovered);
    free(cipher);
    // END OneShot
  }
}

// -----------------------------------------------------------------------------

class Chacha20Poly1305Testing
  : public ::testing::TestWithParam<chacha20poly1305_test_vector>
{};

TEST_P(Chacha20Poly1305Testing, TryTestVectors)
{
  // Initialize CPU feature detection
  hacl_init_cpu_features();

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
  // We might have compiled vec128 chachapoly but don't have it available on the
  // CPU when running now.
  if (hacl_vec128_support()) {
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
  } else {
    printf(" ! Vec128 was compiled but it is not available on this CPU.\n");
  }
#endif // HACL_CAN_COMPILE_VEC128

#ifdef HACL_CAN_COMPILE_VEC256
  // We might have compiled vec256 chachapoly but don't have it available on the
  // CPU when running now.
  if (hacl_vec256_support()) {
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
  } else {
    printf(" ! Vec256 was compiled but it is not available on this CPU.\n");
  }
#endif // HACL_CAN_COMPILE_VEC256
}

INSTANTIATE_TEST_SUITE_P(TestVectors,
                         Chacha20Poly1305Testing,
                         ::testing::ValuesIn(vectors));

// === Wycheproof tests === //

class Chacha20Poly1305Wycheproof
  : public ::testing::TestWithParam<WycheproofAeadTest>
{};

TEST_P(Chacha20Poly1305Wycheproof, TryWycheproof)
{
  // Initialize CPU feature detection
  hacl_init_cpu_features();
  const WycheproofAeadTest& test_case(GetParam());

  auto msg_size = test_case.msg.size();
  bytes plaintext(msg_size, 0);
  bytes ciphertext(msg_size, 0);
  uint8_t mac[16] = { 0 };

  // Stupid const
  uint8_t* key = const_cast<uint8_t*>(test_case.key.data());
  uint8_t* iv = const_cast<uint8_t*>(test_case.iv.data());
  uint8_t* aad = const_cast<uint8_t*>(test_case.aad.data());
  uint8_t* msg = const_cast<uint8_t*>(test_case.msg.data());
  uint8_t* tag = const_cast<uint8_t*>(test_case.tag.data());
  uint8_t* ct = const_cast<uint8_t*>(test_case.ct.data());

  // Check that encryption yields the expected cipher text.
  Hacl_Chacha20Poly1305_32_aead_encrypt(
    key, iv, test_case.aad.size(), aad, msg_size, msg, ciphertext.data(), mac);
  if (test_case.valid) {
    EXPECT_EQ(ciphertext, test_case.ct);
    EXPECT_EQ(std::vector<uint8_t>(mac, mac + 16), test_case.tag);
  }

  int res = Hacl_Chacha20Poly1305_32_aead_decrypt(
    key, iv, test_case.aad.size(), aad, msg_size, plaintext.data(), ct, tag);
  EXPECT_EQ(res, test_case.valid ? 0 : 1);

  {
    bytes got_ct = bytes(test_case.msg.size());
    Hacl_Chacha20_Vec32_chacha20_encrypt_32(
      test_case.msg.size(), got_ct.data(), msg, key, iv, 1);

    ASSERT_EQ(test_case.ct, got_ct);

    bytes got_msg = bytes(test_case.msg.size());
    Hacl_Chacha20_Vec32_chacha20_decrypt_32(
      test_case.msg.size(), got_msg.data(), ct, key, iv, 1);

    ASSERT_EQ(test_case.msg, got_msg);
  }

// XXX: do less c&p
#ifdef HACL_CAN_COMPILE_VEC128
  // We might have compiled vec128 chachapoly but don't have it available on the
  // CPU when running now.
  if (hacl_vec128_support()) {
    // Check that encryption yields the expected cipher text.
    Hacl_Chacha20Poly1305_128_aead_encrypt(key,
                                           iv,
                                           test_case.aad.size(),
                                           aad,
                                           msg_size,
                                           msg,
                                           ciphertext.data(),
                                           mac);
    if (test_case.valid) {
      EXPECT_EQ(ciphertext, test_case.ct);
      EXPECT_EQ(std::vector<uint8_t>(mac, mac + 16), test_case.tag);
    }

    res = Hacl_Chacha20Poly1305_128_aead_decrypt(
      key, iv, test_case.aad.size(), aad, msg_size, plaintext.data(), ct, tag);
    EXPECT_EQ(res, test_case.valid ? 0 : 1);
  } else {
    printf(" ! Vec128 was compiled but it is not available on this CPU.\n");
  }
#endif //  HACL_CAN_COMPILE_VEC128

// XXX: do less c&p
#ifdef HACL_CAN_COMPILE_VEC256
  // We might have compiled vec256 chachapoly but don't have it available on the
  // CPU when running now.
  if (hacl_vec256_support()) {
    // Check that encryption yields the expected cipher text.
    Hacl_Chacha20Poly1305_256_aead_encrypt(key,
                                           iv,
                                           test_case.aad.size(),
                                           aad,
                                           msg_size,
                                           msg,
                                           ciphertext.data(),
                                           mac);
    if (test_case.valid) {
      EXPECT_EQ(ciphertext, test_case.ct);
      EXPECT_EQ(std::vector<uint8_t>(mac, mac + 16), test_case.tag);
    }

    res = Hacl_Chacha20Poly1305_256_aead_decrypt(
      key, iv, test_case.aad.size(), aad, msg_size, plaintext.data(), ct, tag);
    EXPECT_EQ(res, test_case.valid ? 0 : 1);
  } else {
    printf(" ! Vec256 was compiled but it is not available on this CPU.\n");
  }
#endif //  HACL_CAN_COMPILE_VEC256
}

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         Chacha20Poly1305Wycheproof,
                         ::testing::ValuesIn(read_wycheproof_aead_json(
                           "chacha20_poly1305_test.json")));
