/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <gtest/gtest.h>

#include "evercrypt.h"
#include "util.h"

using namespace std;

typedef EverCryptSuite<string> EverCryptSuiteDummy;

TEST_P(EverCryptSuiteDummy, CheckDisabledFeatures)
{
  // The SetUp() method should have applied this config.
  EverCryptConfig config;
  string name;
  tie(config, name) = this->GetParam();

  // Let's check if the features were really disabled.
  if (config.disable_adx) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_adx());
  }
  if (config.disable_aesni) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_aesni());
  }
  if (config.disable_avx) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_avx());
  }
  if (config.disable_avx2) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_avx2());
  }
  if (config.disable_avx512) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_avx512());
  }
  if (config.disable_bmi2) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_bmi2());
  }
  if (config.disable_movbe) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_movbe());
  }
  if (config.disable_pclmulqdq) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_pclmulqdq());
  }
  if (config.disable_rdrand) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_rdrand());
  }
  if (config.disable_shaext) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_shaext());
  }
  if (config.disable_sse) {
    ASSERT_FALSE(EverCrypt_AutoConfig2_has_sse());
  }
}

INSTANTIATE_TEST_SUITE_P(
  Exhaustive,
  EverCryptSuiteDummy,
  ::testing::Combine(::testing::ValuesIn(exhaustive_evercrypt_config_list()),
                     ::testing::ValuesIn({ string("") })));
