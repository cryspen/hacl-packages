/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <gtest/gtest.h>
#include <ostream>

#include "EverCrypt_AutoConfig2.h"

using namespace std;

class EverCryptConfig
{
public:
  bool disable_adx;
  bool disable_aesni;
  bool disable_avx;
  bool disable_avx2;
  bool disable_avx512;
  bool disable_bmi2;
  bool disable_movbe;
  bool disable_pclmulqdq;
  bool disable_rdrand;
  bool disable_shaext;
  bool disable_sse;
};

ostream&
operator<<(ostream& os, const EverCryptConfig& config)
{
  os << "EverCryptConfig {" << endl
     << "\t.disable_adx = " << config.disable_adx << endl
     << "\t.disable_aesni = " << config.disable_aesni << endl
     << "\t.disable_avx = " << config.disable_avx << endl
     << "\t.disable_avx2 = " << config.disable_avx2 << endl
     << "\t.disable_avx512 = " << config.disable_avx512 << endl
     << "\t.disable_bmi2 = " << config.disable_bmi2 << endl
     << "\t.disable_movbe = " << config.disable_movbe << endl
     << "\t.disable_pclmulqdq = " << config.disable_pclmulqdq << endl
     << "\t.disable_rdrand = " << config.disable_rdrand << endl
     << "\t.disable_shaext = " << config.disable_shaext << endl
     << "\t.disable_sse = " << config.disable_sse << endl
     << "}" << endl;
  return os;
}

template<class T>
class EverCryptSuite
  : public ::testing::TestWithParam<tuple<EverCryptConfig, T>>
{
protected:
  void SetUp() override
  {
    EverCryptConfig config;
    T test;
    tie(config, test) = this->GetParam();
    this->apply_evercrypt_config(config);
  }

private:
  void apply_evercrypt_config(EverCryptConfig config)
  {
    EverCrypt_AutoConfig2_init();

    if (config.disable_adx) {
      EverCrypt_AutoConfig2_disable_adx();
    }
    if (config.disable_aesni) {
      EverCrypt_AutoConfig2_disable_aesni();
    }
    if (config.disable_avx) {
      EverCrypt_AutoConfig2_disable_avx();
    }
    if (config.disable_avx2) {
      EverCrypt_AutoConfig2_disable_avx2();
    }
    if (config.disable_avx512) {
      EverCrypt_AutoConfig2_disable_avx512();
    }
    if (config.disable_bmi2) {
      EverCrypt_AutoConfig2_disable_bmi2();
    }
    if (config.disable_movbe) {
      EverCrypt_AutoConfig2_disable_movbe();
    }
    if (config.disable_pclmulqdq) {
      EverCrypt_AutoConfig2_disable_pclmulqdq();
    }
    if (config.disable_rdrand) {
      EverCrypt_AutoConfig2_disable_rdrand();
    }
    if (config.disable_shaext) {
      EverCrypt_AutoConfig2_disable_shaext();
    }
    if (config.disable_sse) {
      EverCrypt_AutoConfig2_disable_sse();
    }
  }
};

// Generate all combinations of `_disable`d features.
vector<EverCryptConfig>
exhaustive_evercrypt_config_list()
{
  vector<EverCryptConfig> tests;

  // We treat a number i as a bit vector.
  // `Config` has 11 fields, i.e., 2^11=2048 possible settings.
  for (uint32_t i = 0; i < 2048; ++i) {
    tests.push_back(EverCryptConfig{
      .disable_adx = (i & 1) != 0,
      .disable_aesni = (i & 2) != 0,
      .disable_avx = (i & 4) != 0,
      .disable_avx2 = (i & 8) != 0,
      .disable_avx512 = (i & 16) != 0,
      .disable_bmi2 = (i & 32) != 0,
      .disable_movbe = (i & 64) != 0,
      .disable_pclmulqdq = (i & 128) != 0,
      .disable_rdrand = (i & 256) != 0,
      .disable_shaext = (i & 512) != 0,
      .disable_sse = (i & 1024) != 0,
    });
  }

  return tests;
}
