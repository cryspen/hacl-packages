/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <gtest/gtest.h>

#include "EverCrypt_AEAD.h"
#include "evercrypt.h"
#include "util.h"
#include "wycheproof.h"

using namespace std;

// ----- EverCrypt -------------------------------------------------------------

void
encrypt_decrypt(EverCrypt_AEAD_state_s* state,
                bytes& iv,
                bytes& aad,
                bytes& msg,
                bytes& cipher,
                bytes& tag,
                bool valid)
{
  // Encrypt
  {
    bytes got_cipher(cipher.size());
    bytes got_tag(tag.size());
    EverCrypt_Error_error_code res = EverCrypt_AEAD_encrypt(state,
                                                            iv.data(),
                                                            iv.size(),
                                                            aad.data(),
                                                            aad.size(),
                                                            msg.data(),
                                                            msg.size(),
                                                            got_cipher.data(),
                                                            got_tag.data());

    if (valid) {
      ASSERT_EQ(res, 0);
      ASSERT_EQ(cipher, got_cipher);
      ASSERT_EQ(tag, got_tag);
    }
  }

  // Decrypt
  {
    bytes got_msg(msg.size());
    EverCrypt_Error_error_code res = EverCrypt_AEAD_decrypt(state,
                                                            iv.data(),
                                                            iv.size(),
                                                            aad.data(),
                                                            aad.size(),
                                                            cipher.data(),
                                                            cipher.size(),
                                                            tag.data(),
                                                            got_msg.data());

    if (valid) {
      ASSERT_EQ(res, 0);
      ASSERT_EQ(msg, got_msg);
    } else {
      ASSERT_NE(res, 0);
    }
  }
}

// ----- ChaCha20Poly1305 ------------------------------------------------------

typedef EverCryptSuite<WycheproofChacha20Poly1305> ChaCha20Suite;

TEST_P(ChaCha20Suite, KAT)
{
  EverCryptConfig config;
  WycheproofChacha20Poly1305 test;
  tie(config, test) = this->GetParam();

  EverCrypt_AEAD_state_s* state;
  EverCrypt_AEAD_create_in(
    Spec_Agile_AEAD_CHACHA20_POLY1305, &state, test.key.data());

  encrypt_decrypt(
    state, test.iv, test.aad, test.msg, test.ct, test.tag, test.valid);

  EverCrypt_AEAD_free(state);
}

// ----- AES GCM -------------------------------------------------------------

typedef EverCryptSuite<WycheproofAesGcm> AesGcmSuite;

TEST_P(AesGcmSuite, KAT)
{
  EverCryptConfig config;
  WycheproofAesGcm test;
  tie(config, test) = this->GetParam();

  EverCrypt_AEAD_state_s* state;

  if (test.iv.size() != 12) {
    cout << "Skipping ivSize != 96" << endl;
    return;
  }

  EverCrypt_Error_error_code res;
  if (test.keySize == 128) {
    res = EverCrypt_AEAD_create_in(
      Spec_Agile_AEAD_AES128_GCM, &state, test.key.data());
  } else if (test.keySize == 192) {
    cout << "Skipping keySize = 192" << endl;
    return;
  } else if (test.keySize == 256) {
    res = EverCrypt_AEAD_create_in(
      Spec_Agile_AEAD_AES256_GCM, &state, test.key.data());
  } else {
    FAIL() << "Unexpected keySize.";
  }

  if (res != EverCrypt_Error_Success) {
    cout << "Skipping test due to EverCrypt error" << res << endl;
    return;
  }

  encrypt_decrypt(
    state, test.iv, test.aad, test.msg, test.ct, test.tag, test.valid);
}

// ----- EverCrypt -------------------------------------------------------------

// AEAD can use aesni, clmul, VEC128 (avx on Intel), and VEC256 (avx2 on Intel).
vector<EverCryptConfig>
generate_aead_configs()
{
  vector<EverCryptConfig> configs;

  for (uint32_t i = 0; i < 16; ++i) {
    configs.push_back(EverCryptConfig{
      .disable_adx = false,
      .disable_aesni = (i % 1) != 0,
      .disable_avx = (i & 2) != 0,
      .disable_avx2 = (i & 4) != 0,
      .disable_avx512 = false,
      .disable_bmi2 = false,
      .disable_movbe = false,
      .disable_pclmulqdq = (i % 8) != 0,
      .disable_rdrand = false,
      .disable_shaext = false,
      .disable_sse = false,
    });
  }

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  ChaCha20Suite,
  ::testing::Combine(::testing::ValuesIn(generate_aead_configs()),
                     ::testing::ValuesIn(read_wycheproof_chacha20_poly1305_json(
                       "chacha20_poly1305_test.json"))));

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  AesGcmSuite,
  ::testing::Combine(
    ::testing::ValuesIn(generate_aead_configs()),
    ::testing::ValuesIn(read_aes_gcm_json("aes_gcm_test.json"))));
