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

#include "Hacl_Bignum32.h"
#include "Hacl_GenericField32.h"
#include "hacl-cpu-features.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Bignum64.h"
#include "Hacl_GenericField64.h"
#endif

using namespace std;
using json = nlohmann::json;

class TestCase
{
public:
  uint32_t limbs32;
  uint32_t limbs64;
  bytes a;
  bytes b;
  uint32_t bBits;
  bytes n;
  bytes add;
  bytes sub;
  bytes mul;
  bytes sqr;
  bytes exp;
  bytes inv;
};

ostream&
operator<<(ostream& os, const TestCase& test)
{
  os << "TestCase {" << endl
     << "\t.limbs32 = " << test.limbs32 << endl
     << "\t.limbs64 = " << test.limbs64 << endl
     << "\t.a = " << bytes_to_hex(test.a) << endl
     << "\t.b = " << bytes_to_hex(test.b) << endl
     << "\t.bBits = " << test.bBits << endl
     << "\t.n = " << bytes_to_hex(test.n) << endl
     << "\t.add = " << bytes_to_hex(test.add) << endl
     << "\t.sub = " << bytes_to_hex(test.sub) << endl
     << "\t.mul = " << bytes_to_hex(test.mul) << endl
     << "\t.sqr = " << bytes_to_hex(test.sqr) << endl
     << "\t.exp = " << bytes_to_hex(test.exp) << endl
     << "\t.inv = " << bytes_to_hex(test.inv) << endl
     << "}" << endl;
  return os;
}

// -----------------------------------------------------------------------------

class GenericFieldSuite : public ::testing::TestWithParam<TestCase>
{};

uint32_t*
new_bn_32(bytes hex)
{
  uint32_t* bn = Hacl_Bignum32_new_bn_from_bytes_be(hex.size(), hex.data());
  EXPECT_NE(bn, (uint32_t*)nullptr);

  return bn;
}

uint32_t*
new_M_32(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u32* ctx,
         bytes hex,
         uint32_t limbs)
{
  uint32_t* bn = Hacl_Bignum32_new_bn_from_bytes_be(hex.size(), hex.data());
  EXPECT_NE(bn, (uint32_t*)nullptr);

  uint32_t* out = (uint32_t*)malloc(sizeof(uint32_t) * limbs);
  Hacl_GenericField32_to_field(ctx, bn, out);
  free(bn);

  return out;
}

TEST_P(GenericFieldSuite, Toy32)
{
  // Suffix M (Montgomery)
  // No Suffix (Bignum)

  TestCase test = GetParam();

  // Init
  uint32_t* n = new_bn_32(test.n);

  bool will_work = Hacl_GenericField32_field_modulus_check(test.limbs32, n);
  ASSERT_TRUE(will_work);

  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u32* ctx =
    Hacl_GenericField32_field_init(test.limbs32, n);
  ASSERT_NE(ctx, (Hacl_Bignum_MontArithmetic_bn_mont_ctx_u32*)nullptr);

  uint32_t modulus_size = Hacl_GenericField32_field_get_len(ctx);
  ASSERT_EQ(modulus_size, test.limbs32);

  // ---------------------------------------------------------------------------

  uint32_t* a = new_bn_32(test.a);
  uint32_t* b = new_bn_32(test.b);
  uint32_t* r = new_bn_32(test.a);

  uint32_t* aM = new_M_32(ctx, test.a, test.limbs32);
  uint32_t* bM = new_M_32(ctx, test.b, test.limbs32);
  uint32_t* rM = new_M_32(ctx, test.a, test.limbs32);

  // Add
  {
    Hacl_GenericField32_add(ctx, aM, bM, rM);
    Hacl_GenericField32_from_field(ctx, rM, r);

    uint32_t* expected = new_bn_32(test.add);
    ASSERT_EQ(memcmp(r, expected, test.limbs32 * 4), 0);
    free(expected);
  }

  // Sub
  {
    Hacl_GenericField32_sub(ctx, aM, bM, rM);
    Hacl_GenericField32_from_field(ctx, rM, r);

    uint32_t* expected = new_bn_32(test.sub);
    ASSERT_EQ(memcmp(r, expected, test.limbs32 * 4), 0);
    free(expected);
  }

  // Mul
  {
    Hacl_GenericField32_mul(ctx, aM, bM, rM);
    Hacl_GenericField32_from_field(ctx, rM, r);

    uint32_t* expected = new_bn_32(test.mul);
    ASSERT_EQ(memcmp(r, expected, test.limbs32 * 4), 0);
    free(expected);
  }

  // Sqr
  {
    Hacl_GenericField32_sqr(ctx, aM, rM);
    Hacl_GenericField32_from_field(ctx, rM, r);

    uint32_t* expected = new_bn_32(test.sqr);
    ASSERT_EQ(memcmp(r, expected, test.limbs32 * 4), 0);
    free(expected);
  }

  // exp (consttime)
  {
    Hacl_GenericField32_exp_consttime(ctx, aM, test.bBits, b, rM);
    Hacl_GenericField32_from_field(ctx, rM, r);

    uint32_t* expected = new_bn_32(test.exp);
    ASSERT_EQ(memcmp(r, expected, test.limbs32 * 4), 0);
    free(expected);
  }

  // exp (vartime)
  {
    Hacl_GenericField32_exp_vartime(ctx, aM, test.bBits, b, rM);
    Hacl_GenericField32_from_field(ctx, rM, r);

    uint32_t* expected = new_bn_32(test.exp);
    ASSERT_EQ(memcmp(r, expected, test.limbs32 * 4), 0);
    free(expected);
  }

  // inverse
  {
    Hacl_GenericField32_inverse(ctx, aM, rM);
    Hacl_GenericField32_from_field(ctx, rM, r);

    uint32_t* expected = new_bn_32(test.inv);
    ASSERT_EQ(memcmp(r, expected, test.limbs32 * 4), 0);
    free(expected);
  }

  // Finish
  free(rM);
  free(bM);
  free(aM);

  free(r);
  free(b);
  free(a);

  Hacl_GenericField32_field_free(ctx);
  free(n);
}

#ifdef HACL_CAN_COMPILE_VEC128
uint64_t*
new_bn_64(bytes hex)
{
  uint64_t* bn = Hacl_Bignum64_new_bn_from_bytes_be(hex.size(), hex.data());
  EXPECT_NE(bn, (uint64_t*)nullptr);

  return bn;
}

uint64_t*
new_M_64(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* ctx,
         bytes hex,
         uint32_t limbs)
{
  uint64_t* bn = Hacl_Bignum64_new_bn_from_bytes_be(hex.size(), hex.data());
  EXPECT_NE(bn, (uint64_t*)nullptr);

  uint64_t* out = (uint64_t*)malloc(sizeof(uint64_t) * limbs);
  Hacl_GenericField64_to_field(ctx, bn, out);
  free(bn);

  return out;
}
#endif

TEST_P(GenericFieldSuite, Toy64)
{
  hacl_init_cpu_features();

  // Suffix M (Montgomery)
  // No Suffix (Bignum)

  TestCase test = GetParam();

#ifdef HACL_CAN_COMPILE_VEC128
  if (hacl_vec128_support()) {
    // Init
    uint64_t* n = new_bn_64(test.n);

    bool will_work = Hacl_GenericField64_field_modulus_check(test.limbs64, n);
    ASSERT_TRUE(will_work);

    Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64* ctx =
      Hacl_GenericField64_field_init(test.limbs64, n);
    ASSERT_NE(ctx, (Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64*)nullptr);

    uint64_t modulus_size = Hacl_GenericField64_field_get_len(ctx);
    ASSERT_EQ(modulus_size, test.limbs64);

    // ---------------------------------------------------------------------------

    uint64_t* a = new_bn_64(test.a);
    uint64_t* b = new_bn_64(test.b);
    uint64_t* r = new_bn_64(test.a);

    uint64_t* aM = new_M_64(ctx, test.a, test.limbs64);
    uint64_t* bM = new_M_64(ctx, test.b, test.limbs64);
    uint64_t* rM = new_M_64(ctx, test.a, test.limbs64);

    // Add
    {
      Hacl_GenericField64_add(ctx, aM, bM, rM);
      Hacl_GenericField64_from_field(ctx, rM, r);

      uint64_t* expected = new_bn_64(test.add);
      ASSERT_EQ(memcmp(r, expected, test.limbs64 * 8), 0);
      free(expected);
    }

    // Sub
    {
      Hacl_GenericField64_sub(ctx, aM, bM, rM);
      Hacl_GenericField64_from_field(ctx, rM, r);

      uint64_t* expected = new_bn_64(test.sub);
      ASSERT_EQ(memcmp(r, expected, test.limbs64 * 8), 0);
      free(expected);
    }

    // Mul
    {
      Hacl_GenericField64_mul(ctx, aM, bM, rM);
      Hacl_GenericField64_from_field(ctx, rM, r);

      uint64_t* expected = new_bn_64(test.mul);
      ASSERT_EQ(memcmp(r, expected, test.limbs64 * 8), 0);
      free(expected);
    }

    // Sqr
    {
      Hacl_GenericField64_sqr(ctx, aM, rM);
      Hacl_GenericField64_from_field(ctx, rM, r);

      uint64_t* expected = new_bn_64(test.sqr);
      ASSERT_EQ(memcmp(r, expected, test.limbs64 * 8), 0);
      free(expected);
    }

    // exp (consttime)
    {
      Hacl_GenericField64_exp_consttime(ctx, aM, test.bBits, b, rM);
      Hacl_GenericField64_from_field(ctx, rM, r);

      uint64_t* expected = new_bn_64(test.exp);
      ASSERT_EQ(memcmp(r, expected, test.limbs64 * 8), 0);
      free(expected);
    }

    // exp (vartime)
    {
      Hacl_GenericField64_exp_vartime(ctx, aM, test.bBits, b, rM);
      Hacl_GenericField64_from_field(ctx, rM, r);

      uint64_t* expected = new_bn_64(test.exp);
      ASSERT_EQ(memcmp(r, expected, test.limbs64 * 8), 0);
      free(expected);
    }

    // inverse
    {
      Hacl_GenericField64_inverse(ctx, aM, rM);
      Hacl_GenericField64_from_field(ctx, rM, r);

      uint64_t* expected = new_bn_64(test.inv);
      ASSERT_EQ(memcmp(r, expected, test.limbs64 * 8), 0);
      free(expected);
    }

    // Finish
    free(rM);
    free(bM);
    free(aM);

    free(r);
    free(b);
    free(a);

    Hacl_GenericField64_field_free(ctx);
    free(n);
  } else {
    cout << "CPU does not support VEC128." << endl;
  }
#else
  cout << "VEC128 not compiled." << endl;
#endif
}

// -----------------------------------------------------------------------------

vector<TestCase>
read_generic_fields_json(string path)
{
  ifstream json_test_file(path);
  json tests_raw;
  json_test_file >> tests_raw;

  vector<TestCase> tests;

  for (auto& test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    uint32_t limbs32 = test["limbs32"];
    uint32_t limbs64 = test["limbs64"];
    bytes a = from_hex(test["a"]);
    bytes b = from_hex(test["b"]);
    uint32_t bBits = test["bBits"];
    bytes n = from_hex(test["n"]);
    bytes add = from_hex(test["add"]);
    bytes sub = from_hex(test["sub"]);
    bytes mul = from_hex(test["mul"]);
    bytes sqr = from_hex(test["sqr"]);
    bytes exp = from_hex(test["exp"]);
    bytes inv = from_hex(test["inv"]);

    tests.push_back(TestCase{
      .limbs32 = limbs32,
      .limbs64 = limbs64,
      .a = a,
      .b = b,
      .bBits = bBits,
      .n = n,
      .add = add,
      .sub = sub,
      .mul = mul,
      .sqr = sqr,
      .exp = exp,
      .inv = inv,
    });
  }

  return tests;
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  Cryspen,
  GenericFieldSuite,
  ::testing::ValuesIn(read_generic_fields_json("generic_field.json")));
