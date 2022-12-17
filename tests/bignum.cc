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

#include "Hacl_Bignum256_32.h"
#include "Hacl_Bignum32.h"
#include "Hacl_Bignum4096_32.h"
#include "config.h"
#include "evercrypt.h"
#include "hacl-cpu-features.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Bignum256.h"
#include "Hacl_Bignum4096.h"
#include "Hacl_Bignum64.h"
#endif

using namespace std;
using json = nlohmann::json;

class TestCase
{
public:
  uint32_t length;
  bytes a;
  bytes b;
  bytes n;
  bytes add;
  uint32_t add_carry;
  bytes add_mod;
  bytes sub;
  uint32_t sub_carry;
  bytes sub_mod;
  bytes sqr;
  bytes exp_mod;
};

ostream&
operator<<(ostream& os, const TestCase& test)
{
  os << "TestCase {" << endl
     << "\t.length = " << test.length << "," << endl
     << "\t.a = " << bytes_to_hex(test.a) << "," << endl
     << "\t.b = " << bytes_to_hex(test.b) << "," << endl
     << "\t.n = " << bytes_to_hex(test.n) << "," << endl
     << "\t.add = " << bytes_to_hex(test.add) << "," << endl
     << "\t.add_carry = " << test.add_carry << "," << endl
     << "\t.add_mod = " << bytes_to_hex(test.add_mod) << "," << endl
     << "\t.sub = " << bytes_to_hex(test.sub) << "," << endl
     << "\t.sub_carry = " << test.sub_carry << "," << endl
     << "\t.sub_mod = " << bytes_to_hex(test.sub_mod) << "," << endl
     << "\t.sqr = " << bytes_to_hex(test.sqr) << "," << endl
     << "\t.exp_mod = " << bytes_to_hex(test.exp_mod) << "," << endl
     << "}" << endl;

  return os;
}

class Bignum : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Bignum, KAT)
{
  hacl_init_cpu_features();

  auto test = GetParam();

  // 32-Bit
  {
    // This is all used to reduce duplicate code for the 256 and 4096 variants.
    typedef uint32_t* (*Bytes_be_to_bn_32)(uint32_t, uint8_t*);
    typedef void (*Bn_to_bytes_be_32)(uint32_t*, uint8_t*);
    typedef uint32_t (*Add_32)(uint32_t*, uint32_t*, uint32_t*);
    typedef void (*AddMod_32)(uint32_t*, uint32_t*, uint32_t*, uint32_t*);
    typedef uint32_t (*Sub_32)(uint32_t*, uint32_t*, uint32_t*);
    typedef void (*SubMod_32)(uint32_t*, uint32_t*, uint32_t*, uint32_t*);
    typedef bool (*Mod_32)(uint32_t*, uint32_t*, uint32_t*);
    typedef void (*Sqr_32)(uint32_t*, uint32_t*);

    uint32_t length;
    Bytes_be_to_bn_32 bytes_be_to_bn_fixed_32;
    Bn_to_bytes_be_32 bn_to_bytes_be_fixed_32;
    Add_32 add_32;
    AddMod_32 add_mod_32;
    Sub_32 sub_32;
    SubMod_32 sub_mod_32;
    Mod_32 mod_32;
    Sqr_32 sqr_32;

    if (test.length == 256) {
      length = 256;
      bytes_be_to_bn_fixed_32 = Hacl_Bignum256_32_new_bn_from_bytes_be;
      bn_to_bytes_be_fixed_32 = Hacl_Bignum256_32_bn_to_bytes_be;
      add_32 = Hacl_Bignum256_32_add;
      add_mod_32 = Hacl_Bignum256_32_add_mod;
      sub_32 = Hacl_Bignum256_32_sub;
      sub_mod_32 = Hacl_Bignum256_32_sub_mod;
      mod_32 = Hacl_Bignum256_32_mod;
      sqr_32 = Hacl_Bignum256_32_sqr;
    } else if (test.length == 4096) {
      length = 4096;
      bytes_be_to_bn_fixed_32 = Hacl_Bignum4096_32_new_bn_from_bytes_be;
      bn_to_bytes_be_fixed_32 = Hacl_Bignum4096_32_bn_to_bytes_be;
      add_32 = Hacl_Bignum4096_32_add;
      add_mod_32 = Hacl_Bignum4096_32_add_mod;
      sub_32 = Hacl_Bignum4096_32_sub;
      sub_mod_32 = Hacl_Bignum4096_32_sub_mod;
      mod_32 = Hacl_Bignum4096_32_mod;
      sqr_32 = Hacl_Bignum4096_32_sqr;
    } else {
      FAIL() << "Unexpected length.";
    }

    // a
    uint32_t* a_bn = bytes_be_to_bn_fixed_32(test.a.size(), test.a.data());
    ASSERT_NE(a_bn, (uint32_t*)nullptr);

    // b
    uint32_t* b_bn = bytes_be_to_bn_fixed_32(test.b.size(), test.b.data());
    ASSERT_NE(b_bn, (uint32_t*)nullptr);

    bytes empty(length, 0);

    // a (double)
    bytes a_double = empty;
    a_double.insert(a_double.end(), test.a.begin(), test.a.end());
    uint32_t* a_bn_double =
      Hacl_Bignum32_new_bn_from_bytes_be(a_double.size(), a_double.data());
    ASSERT_NE(a_bn_double, (uint32_t*)nullptr);

    // b (double)
    bytes b_double = empty;
    b_double.insert(b_double.end(), test.b.begin(), test.b.end());
    uint32_t* b_bn_double =
      Hacl_Bignum32_new_bn_from_bytes_be(b_double.size(), b_double.data());
    ASSERT_NE(b_bn_double, (uint32_t*)nullptr);

    // n
    uint32_t* n_bn = bytes_be_to_bn_fixed_32(test.n.size(), test.n.data());
    ASSERT_NE(n_bn, (uint32_t*)nullptr);

    // add
    {
      bytes empty(length / 8, 0);
      uint32_t* got_res_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint32_t*)nullptr);

      uint32_t got_carry = add_32(a_bn, b_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_32(got_res_bn, got_res.data());

      ASSERT_EQ(test.add, got_res);
      ASSERT_EQ(test.add_carry, got_carry);

      free(got_res_bn);
    }

    // add mod n
    {
      bytes empty(length / 8, 0);

      // Ensure a is < n
      uint32_t* a_reduced_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(a_reduced_bn, (uint32_t*)nullptr);
      bool a_res = mod_32(n_bn, a_bn_double, a_reduced_bn);
      ASSERT_TRUE(a_res);

      // Ensure b is < n
      uint32_t* b_reduced_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(b_reduced_bn, (uint32_t*)nullptr);
      bool b_res = mod_32(n_bn, b_bn_double, b_reduced_bn);
      ASSERT_TRUE(b_res);

      uint32_t* got_res_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint32_t*)nullptr);
      add_mod_32(n_bn, a_reduced_bn, b_reduced_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_32(got_res_bn, got_res.data());

      ASSERT_EQ(test.add_mod, got_res);

      free(got_res_bn);
      free(b_reduced_bn);
      free(a_reduced_bn);
    }

    // sub
    {
      bytes empty(length / 8, 0);
      uint32_t* got_res_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint32_t*)nullptr);

      uint32_t got_carry = sub_32(a_bn, b_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_32(got_res_bn, got_res.data());

      ASSERT_EQ(test.sub, got_res);
      ASSERT_EQ(test.sub_carry, got_carry);

      free(got_res_bn);
    }

    // sub mod n
    {
      bytes empty(length / 8, 0);

      // Ensure a is < n
      uint32_t* a_reduced_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(a_reduced_bn, (uint32_t*)nullptr);
      bool a_res = mod_32(n_bn, a_bn_double, a_reduced_bn);
      ASSERT_TRUE(a_res);

      // Ensure b is < n
      uint32_t* b_reduced_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(b_reduced_bn, (uint32_t*)nullptr);
      bool b_res = mod_32(n_bn, b_bn_double, b_reduced_bn);
      ASSERT_TRUE(b_res);

      uint32_t* got_res_bn =
        bytes_be_to_bn_fixed_32(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint32_t*)nullptr);
      sub_mod_32(n_bn, a_reduced_bn, b_reduced_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_32(got_res_bn, got_res.data());

      ASSERT_EQ(test.sub_mod, got_res);

      free(got_res_bn);
      free(b_reduced_bn);
      free(a_reduced_bn);
    }

    // sqr
    {
      bytes empty(length * 2 / 8, 0);
      uint32_t* got_res_bn =
        Hacl_Bignum32_new_bn_from_bytes_be(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint32_t*)nullptr);

      sqr_32(a_bn, got_res_bn);

      bytes got_res(length * 2 / 8, 0);
      Hacl_Bignum32_bn_to_bytes_be(length * 2 / 8, got_res_bn, got_res.data());

      ASSERT_EQ(test.sqr, got_res);

      free(got_res_bn);
    }

    free(n_bn);
    free(b_bn_double);
    free(a_bn_double);
    free(b_bn);
    free(a_bn);
  }

  // 64-Bit
#ifdef HACL_CAN_COMPILE_VEC128
  if (hacl_vec128_support()) {
    // This is all used to reduce duplicate code for the 256 and 4096 variants.
    typedef uint64_t* (*Bytes_be_to_bn_64)(uint32_t, uint8_t*);
    typedef void (*Bn_to_bytes_be_64)(uint64_t*, uint8_t*);
    typedef uint64_t (*Add_64)(uint64_t*, uint64_t*, uint64_t*);
    typedef void (*AddMod_64)(uint64_t*, uint64_t*, uint64_t*, uint64_t*);
    typedef uint64_t (*Sub_64)(uint64_t*, uint64_t*, uint64_t*);
    typedef void (*SubMod_64)(uint64_t*, uint64_t*, uint64_t*, uint64_t*);
    typedef bool (*Mod_64)(uint64_t*, uint64_t*, uint64_t*);
    typedef void (*Sqr_64)(uint64_t*, uint64_t*);

    uint32_t length;
    Bytes_be_to_bn_64 bytes_be_to_bn_fixed_64;
    Bn_to_bytes_be_64 bn_to_bytes_be_fixed_64;
    Add_64 add_64;
    AddMod_64 add_mod_64;
    Sub_64 sub_64;
    SubMod_64 sub_mod_64;
    Mod_64 mod_64;
    Sqr_64 sqr_64;

    if (test.length == 256) {
      length = 256;
      bytes_be_to_bn_fixed_64 = Hacl_Bignum256_new_bn_from_bytes_be;
      bn_to_bytes_be_fixed_64 = Hacl_Bignum256_bn_to_bytes_be;
      add_64 = Hacl_Bignum256_add;
      add_mod_64 = Hacl_Bignum256_add_mod;
      sub_64 = Hacl_Bignum256_sub;
      sub_mod_64 = Hacl_Bignum256_sub_mod;
      mod_64 = Hacl_Bignum256_mod;
      sqr_64 = Hacl_Bignum256_sqr;
    } else if (test.length == 4096) {
      length = 4096;
      bytes_be_to_bn_fixed_64 = Hacl_Bignum4096_new_bn_from_bytes_be;
      bn_to_bytes_be_fixed_64 = Hacl_Bignum4096_bn_to_bytes_be;
      add_64 = Hacl_Bignum4096_add;
      add_mod_64 = Hacl_Bignum4096_add_mod;
      sub_64 = Hacl_Bignum4096_sub;
      sub_mod_64 = Hacl_Bignum4096_sub_mod;
      mod_64 = Hacl_Bignum4096_mod;
      sqr_64 = Hacl_Bignum4096_sqr;
    } else {
      FAIL() << "Unexpected length.";
    }

    // a
    uint64_t* a_bn = bytes_be_to_bn_fixed_64(test.a.size(), test.a.data());
    ASSERT_NE(a_bn, (uint64_t*)nullptr);

    // b
    uint64_t* b_bn = bytes_be_to_bn_fixed_64(test.b.size(), test.b.data());
    ASSERT_NE(b_bn, (uint64_t*)nullptr);

    bytes empty(length, 0);

    // a (double)
    bytes a_double = empty;
    a_double.insert(a_double.end(), test.a.begin(), test.a.end());
    uint64_t* a_bn_double =
      bytes_be_to_bn_fixed_64(a_double.size(), a_double.data());
    ASSERT_NE(a_bn_double, (uint64_t*)nullptr);

    // b (double)
    bytes b_double = empty;
    b_double.insert(b_double.end(), test.b.begin(), test.b.end());
    uint64_t* b_bn_double =
      bytes_be_to_bn_fixed_64(b_double.size(), b_double.data());
    ASSERT_NE(b_bn_double, (uint64_t*)nullptr);

    // n
    uint64_t* n_bn = bytes_be_to_bn_fixed_64(test.n.size(), test.n.data());
    ASSERT_NE(n_bn, (uint64_t*)nullptr);

    // add
    {
      bytes empty(length / 8, 0);
      uint64_t* got_res_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint64_t*)nullptr);

      uint64_t got_carry = add_64(a_bn, b_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_64(got_res_bn, got_res.data());

      ASSERT_EQ(test.add, got_res);
      ASSERT_EQ(test.add_carry, got_carry);

      free(got_res_bn);
    }

    // add mod n
    {
      bytes empty(length / 8, 0);

      // Ensure a is < n
      uint64_t* a_reduced_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(a_reduced_bn, (uint64_t*)nullptr);
      bool a_res = mod_64(n_bn, a_bn_double, a_reduced_bn);
      ASSERT_TRUE(a_res);

      // Ensure b is < n
      uint64_t* b_reduced_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(b_reduced_bn, (uint64_t*)nullptr);
      bool b_res = mod_64(n_bn, b_bn_double, b_reduced_bn);
      ASSERT_TRUE(b_res);

      uint64_t* got_res_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint64_t*)nullptr);
      add_mod_64(n_bn, a_reduced_bn, b_reduced_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_64(got_res_bn, got_res.data());

      ASSERT_EQ(test.add_mod, got_res);

      free(got_res_bn);
      free(b_reduced_bn);
      free(a_reduced_bn);
    }

    // sub
    {
      bytes empty(length / 8, 0);
      uint64_t* got_res_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint64_t*)nullptr);

      uint64_t got_carry = sub_64(a_bn, b_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_64(got_res_bn, got_res.data());

      ASSERT_EQ(test.sub, got_res);
      ASSERT_EQ(test.sub_carry, got_carry);

      free(got_res_bn);
    }

    // sub mod n
    {
      bytes empty(length / 8, 0);

      // Ensure a is < n
      uint64_t* a_reduced_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(a_reduced_bn, (uint64_t*)nullptr);
      bool a_res = mod_64(n_bn, a_bn_double, a_reduced_bn);
      ASSERT_TRUE(a_res);

      // Ensure b is < n
      uint64_t* b_reduced_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(b_reduced_bn, (uint64_t*)nullptr);
      bool b_res = mod_64(n_bn, b_bn_double, b_reduced_bn);
      ASSERT_TRUE(b_res);

      uint64_t* got_res_bn =
        bytes_be_to_bn_fixed_64(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint64_t*)nullptr);
      sub_mod_64(n_bn, a_reduced_bn, b_reduced_bn, got_res_bn);

      bytes got_res(length / 8, 0);
      bn_to_bytes_be_fixed_64(got_res_bn, got_res.data());

      ASSERT_EQ(test.sub_mod, got_res);

      free(got_res_bn);
      free(b_reduced_bn);
      free(a_reduced_bn);
    }

    // sqr
    {
      bytes empty(length * 2 / 8, 0);
      uint64_t* got_res_bn =
        Hacl_Bignum64_new_bn_from_bytes_be(empty.size(), empty.data());
      ASSERT_NE(got_res_bn, (uint64_t*)nullptr);

      sqr_64(a_bn, got_res_bn);

      bytes got_res(length * 2 / 8, 0);
      Hacl_Bignum64_bn_to_bytes_be(length * 2 / 8, got_res_bn, got_res.data());

      ASSERT_EQ(test.sqr, got_res);

      free(got_res_bn);
    }

    free(n_bn);
    free(b_bn_double);
    free(a_bn_double);
    free(b_bn);
    free(a_bn);
  } else {
    cout << "Skipping. No VEC128 support.";
  }
#endif
}

class BignumReduced : public ::testing::TestWithParam<TestCase>
{};

TEST_P(BignumReduced, ModExpKAT)
{
  auto test = GetParam();

  if (test.length == 256) {
    // 32-Bit
    {
      // a
      uint32_t* a_bn =
        Hacl_Bignum256_32_new_bn_from_bytes_be(test.a.size(), test.a.data());
      ASSERT_NE(a_bn, (uint32_t*)nullptr);

      // b
      uint32_t* b_bn =
        Hacl_Bignum256_32_new_bn_from_bytes_be(test.b.size(), test.b.data());
      ASSERT_NE(b_bn, (uint32_t*)nullptr);

      // n
      uint32_t* n_bn =
        Hacl_Bignum256_32_new_bn_from_bytes_be(test.n.size(), test.n.data());
      ASSERT_NE(n_bn, (uint32_t*)nullptr);

      // exp mod
      {
        auto tests = { Hacl_Bignum256_32_mod_exp_consttime,
                       Hacl_Bignum256_32_mod_exp_vartime };

        for (auto mod_exp : tests) {
          bytes empty(256 / 8, 0);

          // a (double)
          bytes a_double = empty;
          a_double.insert(a_double.end(), test.a.begin(), test.a.end());
          uint32_t* a_bn_double = Hacl_Bignum256_32_new_bn_from_bytes_be(
            a_double.size(), a_double.data());
          ASSERT_NE(a_bn_double, (uint32_t*)nullptr);

          // Ensure a is < n
          uint32_t* a_reduced_bn =
            Hacl_Bignum256_32_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(a_reduced_bn, (uint32_t*)nullptr);
          bool a_res = Hacl_Bignum256_32_mod(n_bn, a_bn_double, a_reduced_bn);
          ASSERT_TRUE(a_res);

          uint32_t* got_res_bn =
            Hacl_Bignum256_32_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(got_res_bn, (uint32_t*)nullptr);

          bool got = mod_exp(n_bn, a_reduced_bn, 256, b_bn, got_res_bn);
          EXPECT_TRUE(got);

          bytes got_res(256 / 8, 0);
          Hacl_Bignum256_32_bn_to_bytes_be(got_res_bn, got_res.data());

          ASSERT_EQ(test.exp_mod, got_res);

          free(got_res_bn);
          free(a_reduced_bn);
          free(a_bn_double);
        }
      }

      free(n_bn);
      free(b_bn);
      free(a_bn);
    }

    // 64-Bit
#ifdef HACL_CAN_COMPILE_VEC128
    if (hacl_vec128_support()) {
      // a
      uint64_t* a_bn =
        Hacl_Bignum256_new_bn_from_bytes_be(test.a.size(), test.a.data());
      ASSERT_NE(a_bn, (uint64_t*)nullptr);

      // b
      uint64_t* b_bn =
        Hacl_Bignum256_new_bn_from_bytes_be(test.b.size(), test.b.data());
      ASSERT_NE(b_bn, (uint64_t*)nullptr);

      // n
      uint64_t* n_bn =
        Hacl_Bignum256_new_bn_from_bytes_be(test.n.size(), test.n.data());
      ASSERT_NE(n_bn, (uint64_t*)nullptr);

      // exp mod
      {
        auto tests = { Hacl_Bignum256_mod_exp_consttime,
                       Hacl_Bignum256_mod_exp_vartime };

        for (auto mod_exp : tests) {
          bytes empty(256 / 8, 0);

          // a (double)
          bytes a_double = empty;
          a_double.insert(a_double.end(), test.a.begin(), test.a.end());
          uint64_t* a_bn_double = Hacl_Bignum256_new_bn_from_bytes_be(
            a_double.size(), a_double.data());
          ASSERT_NE(a_bn_double, (uint64_t*)nullptr);

          // Ensure a is < n
          uint64_t* a_reduced_bn =
            Hacl_Bignum256_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(a_reduced_bn, (uint64_t*)nullptr);
          bool a_res = Hacl_Bignum256_mod(n_bn, a_bn_double, a_reduced_bn);
          ASSERT_TRUE(a_res);

          uint64_t* got_res_bn =
            Hacl_Bignum256_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(got_res_bn, (uint64_t*)nullptr);

          bool got = mod_exp(n_bn, a_reduced_bn, 256, b_bn, got_res_bn);
          EXPECT_TRUE(got);

          bytes got_res(256 / 8, 0);
          Hacl_Bignum256_bn_to_bytes_be(got_res_bn, got_res.data());

          ASSERT_EQ(test.exp_mod, got_res);

          free(got_res_bn);
          free(a_reduced_bn);
          free(a_bn_double);
        }
      }

      free(n_bn);
      free(b_bn);
      free(a_bn);
    } else {
      cout << "Skipping. No VEC128 support.";
    }
#endif
  } else if (test.length == 4096) {
    // 32-Bit
    {
      // a
      uint32_t* a_bn =
        Hacl_Bignum4096_32_new_bn_from_bytes_be(test.a.size(), test.a.data());
      ASSERT_NE(a_bn, (uint32_t*)nullptr);

      // b
      uint32_t* b_bn =
        Hacl_Bignum4096_32_new_bn_from_bytes_be(test.b.size(), test.b.data());
      ASSERT_NE(b_bn, (uint32_t*)nullptr);

      // n
      uint32_t* n_bn =
        Hacl_Bignum4096_32_new_bn_from_bytes_be(test.n.size(), test.n.data());
      ASSERT_NE(n_bn, (uint32_t*)nullptr);

      // exp mod
      {
        auto tests = { Hacl_Bignum4096_32_mod_exp_consttime,
                       Hacl_Bignum4096_32_mod_exp_vartime };

        for (auto mod_exp : tests) {
          bytes empty(4096 / 8, 0);

          // a (double)
          bytes a_double = empty;
          a_double.insert(a_double.end(), test.a.begin(), test.a.end());
          uint32_t* a_bn_double = Hacl_Bignum4096_32_new_bn_from_bytes_be(
            a_double.size(), a_double.data());
          ASSERT_NE(a_bn_double, (uint32_t*)nullptr);

          // Ensure a is < n
          uint32_t* a_reduced_bn =
            Hacl_Bignum4096_32_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(a_reduced_bn, (uint32_t*)nullptr);
          bool a_res = Hacl_Bignum4096_32_mod(n_bn, a_bn_double, a_reduced_bn);
          ASSERT_TRUE(a_res);

          uint32_t* got_res_bn =
            Hacl_Bignum4096_32_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(got_res_bn, (uint32_t*)nullptr);

          bool got = mod_exp(n_bn, a_reduced_bn, 4096, b_bn, got_res_bn);
          EXPECT_TRUE(got);

          bytes got_res(4096 / 8, 0);
          Hacl_Bignum4096_32_bn_to_bytes_be(got_res_bn, got_res.data());

          ASSERT_EQ(test.exp_mod, got_res);

          free(got_res_bn);
          free(a_reduced_bn);
          free(a_bn_double);
        }
      }

      free(n_bn);
      free(b_bn);
      free(a_bn);
    }

    // 64-Bit
#ifdef HACL_CAN_COMPILE_VEC128
    if (hacl_vec128_support()) {
      // a
      uint64_t* a_bn =
        Hacl_Bignum4096_new_bn_from_bytes_be(test.a.size(), test.a.data());
      ASSERT_NE(a_bn, (uint64_t*)nullptr);

      // b
      uint64_t* b_bn =
        Hacl_Bignum4096_new_bn_from_bytes_be(test.b.size(), test.b.data());
      ASSERT_NE(b_bn, (uint64_t*)nullptr);

      // n
      uint64_t* n_bn =
        Hacl_Bignum4096_new_bn_from_bytes_be(test.n.size(), test.n.data());
      ASSERT_NE(n_bn, (uint64_t*)nullptr);

      // exp mod
      {
        auto tests = { Hacl_Bignum4096_mod_exp_consttime,
                       Hacl_Bignum4096_mod_exp_vartime };

        for (auto mod_exp : tests) {
          bytes empty(4096 / 8, 0);

          // a (double)
          bytes a_double = empty;
          a_double.insert(a_double.end(), test.a.begin(), test.a.end());
          uint64_t* a_bn_double = Hacl_Bignum4096_new_bn_from_bytes_be(
            a_double.size(), a_double.data());
          ASSERT_NE(a_bn_double, (uint64_t*)nullptr);

          // Ensure a is < n
          uint64_t* a_reduced_bn =
            Hacl_Bignum4096_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(a_reduced_bn, (uint64_t*)nullptr);
          bool a_res = Hacl_Bignum4096_mod(n_bn, a_bn_double, a_reduced_bn);
          ASSERT_TRUE(a_res);

          uint64_t* got_res_bn =
            Hacl_Bignum4096_new_bn_from_bytes_be(empty.size(), empty.data());
          ASSERT_NE(got_res_bn, (uint64_t*)nullptr);

          bool got = mod_exp(n_bn, a_reduced_bn, 4096, b_bn, got_res_bn);
          EXPECT_TRUE(got);

          bytes got_res(4096 / 8, 0);
          Hacl_Bignum4096_bn_to_bytes_be(got_res_bn, got_res.data());

          ASSERT_EQ(test.exp_mod, got_res);

          free(got_res_bn);
          free(a_reduced_bn);
          free(a_bn_double);
        }
      }

      free(n_bn);
      free(b_bn);
      free(a_bn);
    } else {
      cout << "Skipping. No VEC128 support.";
    }
#endif
  } else {
    FAIL() << "Unexpected length.";
  }
}

// -----------------------------------------------------------------------------

vector<TestCase>
read_bignum_json(string path)
{
  std::ifstream json_test_file(path);
  json tests_raw;
  json_test_file >> tests_raw;

  std::vector<TestCase> tests;

  for (auto& test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    uint32_t length = test["length"];
    bytes a = from_hex(test["a"]);
    bytes b = from_hex(test["b"]);
    bytes n = from_hex(test["n"]);
    bytes add = from_hex(test["add"]);
    uint32_t add_carry = test["add_carry"];
    bytes add_mod = from_hex(test["add_mod"]);
    bytes sub = from_hex(test["sub"]);
    uint32_t sub_carry = test["sub_carry"];
    bytes sub_mod = from_hex(test["sub_mod"]);
    bytes sqr = from_hex(test["sqr"]);
    bytes exp_mod = from_hex(test["exp_mod"]);

    // Be cautious.
    assert(a.size() == 256 / 8 || a.size() == 4096 / 8);
    assert(b.size() == 256 / 8 || b.size() == 4096 / 8);
    assert(n.size() == 256 / 8 || n.size() == 4096 / 8);
    assert(sqr.size() == 512 / 8 || sqr.size() == 8192 / 8);

    tests.push_back(TestCase{
      .length = length,
      .a = a,
      .b = b,
      .n = n,
      .add = add,
      .add_carry = add_carry,
      .add_mod = add_mod,
      .sub = sub,
      .sub_carry = sub_carry,
      .sub_mod = sub_mod,
      .sqr = sqr,
      .exp_mod = exp_mod,
    });
  }

  return tests;
}

INSTANTIATE_TEST_SUITE_P(Cryspen,
                         Bignum,
                         ::testing::ValuesIn(read_bignum_json("bignum.json")));

INSTANTIATE_TEST_SUITE_P(Cryspen,
  BignumReduced,
  ::testing::ValuesIn(read_bignum_json("bignum_reduced.json")));
