/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>
#include <gtest/gtest.h>

#include "EverCrypt_AutoConfig2.h"
#include "hacl-cpu-features.h"
#include "util.h"

using namespace std;

class DetectionSuite : public ::testing::Test
{};

TEST(DetectionSuite, PrintFeatures)
{
  // HACL
  {
    cout << "# HACL" << endl;
    hacl_init_cpu_features();

#ifdef HACL_CAN_COMPILE_VEC128
    cout << "HACL_CAN_COMPILE_VEC128: " << 1 << endl;
    cout << "hacl_vec128_support(): " << hacl_vec128_support() << endl;
#else
    cout << "HACL_CAN_COMPILE_VEC128: " << 0 << endl;
#endif

#ifdef HACL_CAN_COMPILE_VEC256
    cout << "HACL_CAN_COMPILE_VEC256: " << 1 << endl;
    cout << "hacl_vec256_support(): " << hacl_vec256_support() << endl;
#else
    cout << "HACL_CAN_COMPILE_VEC256: " << 0 << endl;
#endif
  }

  cout << endl;

  // EverCrypt
  {
    cout << "# EverCrypt" << endl;
    EverCrypt_AutoConfig2_init();

    cout << "adx: " << EverCrypt_AutoConfig2_has_adx() << endl;
    cout << "aesni: " << EverCrypt_AutoConfig2_has_aesni() << endl;
    cout << "avx: " << EverCrypt_AutoConfig2_has_avx() << endl;
    cout << "avx2: " << EverCrypt_AutoConfig2_has_avx2() << endl;
    cout << "avx512: " << EverCrypt_AutoConfig2_has_avx512() << endl;
    cout << "bmi2: " << EverCrypt_AutoConfig2_has_bmi2() << endl;
    cout << "movbe: " << EverCrypt_AutoConfig2_has_movbe() << endl;
    cout << "pclmulqdq: " << EverCrypt_AutoConfig2_has_pclmulqdq() << endl;
    cout << "rdrand: " << EverCrypt_AutoConfig2_has_rdrand() << endl;
    cout << "shaext: " << EverCrypt_AutoConfig2_has_shaext() << endl;
    cout << "sse: " << EverCrypt_AutoConfig2_has_sse() << endl;
  }
}
