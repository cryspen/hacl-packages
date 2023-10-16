/* MIT License
 *
 * Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
 * Copyright (c) 2022-2023 HACL* Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include "Hacl_P384.h"

#include "internal/Hacl_Krmllib.h"
#include "internal/Hacl_Bignum_Base.h"

static inline uint64_t bn_is_eq_mask(uint64_t *x, uint64_t *y)
{
  uint64_t mask = (uint64_t)0xFFFFFFFFFFFFFFFFU;
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t uu____0 = FStar_UInt64_eq_mask(x[i], y[i]);
    mask = uu____0 & mask;);
  uint64_t mask1 = mask;
  return mask1;
}

static inline void bn_cmovznz(uint64_t *a, uint64_t b, uint64_t *c, uint64_t *d)
{
  uint64_t mask = ~FStar_UInt64_eq_mask(b, (uint64_t)0U);
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *os = a;
    uint64_t uu____0 = c[i];
    uint64_t x = uu____0 ^ (mask & (d[i] ^ uu____0));
    os[i] = x;);
}

static inline void bn_add_mod(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d)
{
  uint64_t c10 = (uint64_t)0U;
  {
    uint64_t t1 = c[(uint32_t)4U * (uint32_t)0U];
    uint64_t t20 = d[(uint32_t)4U * (uint32_t)0U];
    uint64_t *res_i0 = a + (uint32_t)4U * (uint32_t)0U;
    c10 = Lib_IntTypes_Intrinsics_add_carry_u64(c10, t1, t20, res_i0);
    uint64_t t10 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t t21 = d[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t *res_i1 = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
    c10 = Lib_IntTypes_Intrinsics_add_carry_u64(c10, t10, t21, res_i1);
    uint64_t t11 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t t22 = d[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t *res_i2 = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
    c10 = Lib_IntTypes_Intrinsics_add_carry_u64(c10, t11, t22, res_i2);
    uint64_t t12 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t t2 = d[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t *res_i = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
    c10 = Lib_IntTypes_Intrinsics_add_carry_u64(c10, t12, t2, res_i);
  }
  KRML_MAYBE_FOR2(i,
    (uint32_t)4U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t t1 = c[i];
    uint64_t t2 = d[i];
    uint64_t *res_i = a + i;
    c10 = Lib_IntTypes_Intrinsics_add_carry_u64(c10, t1, t2, res_i););
  uint64_t c0 = c10;
  uint64_t tmp[6U] = { 0U };
  uint64_t c1 = (uint64_t)0U;
  {
    uint64_t t1 = a[(uint32_t)4U * (uint32_t)0U];
    uint64_t t20 = b[(uint32_t)4U * (uint32_t)0U];
    uint64_t *res_i0 = tmp + (uint32_t)4U * (uint32_t)0U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t1, t20, res_i0);
    uint64_t t10 = a[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t t21 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t *res_i1 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t10, t21, res_i1);
    uint64_t t11 = a[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t t22 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t *res_i2 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t11, t22, res_i2);
    uint64_t t12 = a[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t t2 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t *res_i = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t12, t2, res_i);
  }
  KRML_MAYBE_FOR2(i,
    (uint32_t)4U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t t1 = a[i];
    uint64_t t2 = b[i];
    uint64_t *res_i = tmp + i;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t1, t2, res_i););
  uint64_t c11 = c1;
  uint64_t c2 = c0 - c11;
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *os = a;
    uint64_t x = (c2 & a[i]) | (~c2 & tmp[i]);
    os[i] = x;);
}

static inline uint64_t bn_sub(uint64_t *a, uint64_t *b, uint64_t *c)
{
  uint64_t c1 = (uint64_t)0U;
  {
    uint64_t t1 = b[(uint32_t)4U * (uint32_t)0U];
    uint64_t t20 = c[(uint32_t)4U * (uint32_t)0U];
    uint64_t *res_i0 = a + (uint32_t)4U * (uint32_t)0U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t1, t20, res_i0);
    uint64_t t10 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t t21 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t *res_i1 = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t10, t21, res_i1);
    uint64_t t11 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t t22 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t *res_i2 = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t11, t22, res_i2);
    uint64_t t12 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t t2 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t *res_i = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t12, t2, res_i);
  }
  KRML_MAYBE_FOR2(i,
    (uint32_t)4U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t t1 = b[i];
    uint64_t t2 = c[i];
    uint64_t *res_i = a + i;
    c1 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c1, t1, t2, res_i););
  uint64_t c10 = c1;
  return c10;
}

static inline void bn_sub_mod(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d)
{
  uint64_t c10 = (uint64_t)0U;
  {
    uint64_t t1 = c[(uint32_t)4U * (uint32_t)0U];
    uint64_t t20 = d[(uint32_t)4U * (uint32_t)0U];
    uint64_t *res_i0 = a + (uint32_t)4U * (uint32_t)0U;
    c10 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c10, t1, t20, res_i0);
    uint64_t t10 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t t21 = d[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t *res_i1 = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
    c10 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c10, t10, t21, res_i1);
    uint64_t t11 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t t22 = d[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t *res_i2 = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
    c10 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c10, t11, t22, res_i2);
    uint64_t t12 = c[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t t2 = d[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t *res_i = a + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
    c10 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c10, t12, t2, res_i);
  }
  KRML_MAYBE_FOR2(i,
    (uint32_t)4U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t t1 = c[i];
    uint64_t t2 = d[i];
    uint64_t *res_i = a + i;
    c10 = Lib_IntTypes_Intrinsics_sub_borrow_u64(c10, t1, t2, res_i););
  uint64_t c0 = c10;
  uint64_t tmp[6U] = { 0U };
  uint64_t c1 = (uint64_t)0U;
  {
    uint64_t t1 = a[(uint32_t)4U * (uint32_t)0U];
    uint64_t t20 = b[(uint32_t)4U * (uint32_t)0U];
    uint64_t *res_i0 = tmp + (uint32_t)4U * (uint32_t)0U;
    c1 = Lib_IntTypes_Intrinsics_add_carry_u64(c1, t1, t20, res_i0);
    uint64_t t10 = a[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t t21 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t *res_i1 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
    c1 = Lib_IntTypes_Intrinsics_add_carry_u64(c1, t10, t21, res_i1);
    uint64_t t11 = a[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t t22 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t *res_i2 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
    c1 = Lib_IntTypes_Intrinsics_add_carry_u64(c1, t11, t22, res_i2);
    uint64_t t12 = a[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t t2 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t *res_i = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
    c1 = Lib_IntTypes_Intrinsics_add_carry_u64(c1, t12, t2, res_i);
  }
  KRML_MAYBE_FOR2(i,
    (uint32_t)4U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t t1 = a[i];
    uint64_t t2 = b[i];
    uint64_t *res_i = tmp + i;
    c1 = Lib_IntTypes_Intrinsics_add_carry_u64(c1, t1, t2, res_i););
  uint64_t c11 = c1;
  KRML_HOST_IGNORE(c11);
  uint64_t c2 = (uint64_t)0U - c0;
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *os = a;
    uint64_t x = (c2 & tmp[i]) | (~c2 & a[i]);
    os[i] = x;);
}

static inline void bn_mul(uint64_t *a, uint64_t *b, uint64_t *c)
{
  memset(a, 0U, (uint32_t)12U * sizeof (uint64_t));
  KRML_MAYBE_FOR6(i0,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t bj = c[i0];
    uint64_t *res_j = a + i0;
    uint64_t c1 = (uint64_t)0U;
    {
      uint64_t a_i = b[(uint32_t)4U * (uint32_t)0U];
      uint64_t *res_i0 = res_j + (uint32_t)4U * (uint32_t)0U;
      c1 = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, bj, c1, res_i0);
      uint64_t a_i0 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
      uint64_t *res_i1 = res_j + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
      c1 = Hacl_Bignum_Base_mul_wide_add2_u64(a_i0, bj, c1, res_i1);
      uint64_t a_i1 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
      uint64_t *res_i2 = res_j + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
      c1 = Hacl_Bignum_Base_mul_wide_add2_u64(a_i1, bj, c1, res_i2);
      uint64_t a_i2 = b[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
      uint64_t *res_i = res_j + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
      c1 = Hacl_Bignum_Base_mul_wide_add2_u64(a_i2, bj, c1, res_i);
    }
    KRML_MAYBE_FOR2(i,
      (uint32_t)4U,
      (uint32_t)6U,
      (uint32_t)1U,
      uint64_t a_i = b[i];
      uint64_t *res_i = res_j + i;
      c1 = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, bj, c1, res_i););
    uint64_t r = c1;
    a[(uint32_t)6U + i0] = r;);
}

static inline void bn_sqr(uint64_t *a, uint64_t *b)
{
  memset(a, 0U, (uint32_t)12U * sizeof (uint64_t));
  KRML_MAYBE_FOR6(i0,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *ab = b;
    uint64_t a_j = b[i0];
    uint64_t *res_j = a + i0;
    uint64_t c = (uint64_t)0U;
    for (uint32_t i = (uint32_t)0U; i < i0 / (uint32_t)4U; i++)
    {
      uint64_t a_i = ab[(uint32_t)4U * i];
      uint64_t *res_i0 = res_j + (uint32_t)4U * i;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, a_j, c, res_i0);
      uint64_t a_i0 = ab[(uint32_t)4U * i + (uint32_t)1U];
      uint64_t *res_i1 = res_j + (uint32_t)4U * i + (uint32_t)1U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i0, a_j, c, res_i1);
      uint64_t a_i1 = ab[(uint32_t)4U * i + (uint32_t)2U];
      uint64_t *res_i2 = res_j + (uint32_t)4U * i + (uint32_t)2U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i1, a_j, c, res_i2);
      uint64_t a_i2 = ab[(uint32_t)4U * i + (uint32_t)3U];
      uint64_t *res_i = res_j + (uint32_t)4U * i + (uint32_t)3U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i2, a_j, c, res_i);
    }
    for (uint32_t i = i0 / (uint32_t)4U * (uint32_t)4U; i < i0; i++)
    {
      uint64_t a_i = ab[i];
      uint64_t *res_i = res_j + i;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, a_j, c, res_i);
    }
    uint64_t r = c;
    a[i0 + i0] = r;);
  uint64_t c0 = Hacl_Bignum_Addition_bn_add_eq_len_u64((uint32_t)12U, a, a, a);
  KRML_HOST_IGNORE(c0);
  uint64_t tmp[12U] = { 0U };
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    FStar_UInt128_uint128 res = FStar_UInt128_mul_wide(b[i], b[i]);
    uint64_t hi = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(res, (uint32_t)64U));
    uint64_t lo = FStar_UInt128_uint128_to_uint64(res);
    tmp[(uint32_t)2U * i] = lo;
    tmp[(uint32_t)2U * i + (uint32_t)1U] = hi;);
  uint64_t c1 = Hacl_Bignum_Addition_bn_add_eq_len_u64((uint32_t)12U, a, tmp, a);
  KRML_HOST_IGNORE(c1);
}

static inline void bn_to_bytes_be(uint8_t *a, uint64_t *b)
{
  uint8_t tmp[48U] = { 0U };
  KRML_HOST_IGNORE(tmp);
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    store64_be(a + i * (uint32_t)8U, b[(uint32_t)6U - i - (uint32_t)1U]););
}

static inline void bn_from_bytes_be(uint64_t *a, uint8_t *b)
{
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *os = a;
    uint64_t u = load64_be(b + ((uint32_t)6U - i - (uint32_t)1U) * (uint32_t)8U);
    uint64_t x = u;
    os[i] = x;);
}

static inline void p384_make_prime(uint64_t *n)
{
  n[0U] = (uint64_t)0x00000000ffffffffU;
  n[1U] = (uint64_t)0xffffffff00000000U;
  n[2U] = (uint64_t)0xfffffffffffffffeU;
  n[3U] = (uint64_t)0xffffffffffffffffU;
  n[4U] = (uint64_t)0xffffffffffffffffU;
  n[5U] = (uint64_t)0xffffffffffffffffU;
}

static inline void p384_make_order(uint64_t *n)
{
  n[0U] = (uint64_t)0xecec196accc52973U;
  n[1U] = (uint64_t)0x581a0db248b0a77aU;
  n[2U] = (uint64_t)0xc7634d81f4372ddfU;
  n[3U] = (uint64_t)0xffffffffffffffffU;
  n[4U] = (uint64_t)0xffffffffffffffffU;
  n[5U] = (uint64_t)0xffffffffffffffffU;
}

static inline void p384_make_a_coeff(uint64_t *a)
{
  a[0U] = (uint64_t)0x00000003fffffffcU;
  a[1U] = (uint64_t)0xfffffffc00000000U;
  a[2U] = (uint64_t)0xfffffffffffffffbU;
  a[3U] = (uint64_t)0xffffffffffffffffU;
  a[4U] = (uint64_t)0xffffffffffffffffU;
  a[5U] = (uint64_t)0xffffffffffffffffU;
}

static inline void p384_make_b_coeff(uint64_t *b)
{
  b[0U] = (uint64_t)0x081188719d412dccU;
  b[1U] = (uint64_t)0xf729add87a4c32ecU;
  b[2U] = (uint64_t)0x77f2209b1920022eU;
  b[3U] = (uint64_t)0xe3374bee94938ae2U;
  b[4U] = (uint64_t)0xb62b21f41f022094U;
  b[5U] = (uint64_t)0xcd08114b604fbff9U;
}

static inline void p384_make_g_x(uint64_t *n)
{
  n[0U] = (uint64_t)0x3dd0756649c0b528U;
  n[1U] = (uint64_t)0x20e378e2a0d6ce38U;
  n[2U] = (uint64_t)0x879c3afc541b4d6eU;
  n[3U] = (uint64_t)0x6454868459a30effU;
  n[4U] = (uint64_t)0x812ff723614ede2bU;
  n[5U] = (uint64_t)0x4d3aadc2299e1513U;
}

static inline void p384_make_g_y(uint64_t *n)
{
  n[0U] = (uint64_t)0x23043dad4b03a4feU;
  n[1U] = (uint64_t)0xa1bfa8bf7bb4a9acU;
  n[2U] = (uint64_t)0x8bade7562e83b050U;
  n[3U] = (uint64_t)0xc6c3521968f4ffd9U;
  n[4U] = (uint64_t)0xdd8002263969a840U;
  n[5U] = (uint64_t)0x2b78abc25a15c5e9U;
}

static inline void p384_make_fmont_R2(uint64_t *n)
{
  n[0U] = (uint64_t)0xfffffffe00000001U;
  n[1U] = (uint64_t)0x0000000200000000U;
  n[2U] = (uint64_t)0xfffffffe00000000U;
  n[3U] = (uint64_t)0x0000000200000000U;
  n[4U] = (uint64_t)0x0000000000000001U;
  n[5U] = (uint64_t)0x0U;
}

static inline void p384_make_fzero(uint64_t *n)
{
  memset(n, 0U, (uint32_t)6U * sizeof (uint64_t));
  n[0U] = (uint64_t)0U;
}

static inline void p384_make_fone(uint64_t *n)
{
  n[0U] = (uint64_t)0xffffffff00000001U;
  n[1U] = (uint64_t)0x00000000ffffffffU;
  n[2U] = (uint64_t)0x1U;
  n[3U] = (uint64_t)0x0U;
  n[4U] = (uint64_t)0x0U;
  n[5U] = (uint64_t)0x0U;
}

static inline void p384_make_qone(uint64_t *f)
{
  f[0U] = (uint64_t)0x1313e695333ad68dU;
  f[1U] = (uint64_t)0xa7e5f24db74f5885U;
  f[2U] = (uint64_t)0x389cb27e0bc8d220U;
  f[3U] = (uint64_t)0x0U;
  f[4U] = (uint64_t)0x0U;
  f[5U] = (uint64_t)0x0U;
}

static inline void fmont_reduction(uint64_t *res, uint64_t *x)
{
  uint64_t n[6U] = { 0U };
  p384_make_prime(n);
  uint64_t c0 = (uint64_t)0U;
  KRML_MAYBE_FOR6(i0,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t qj = (uint64_t)4294967297U * x[i0];
    uint64_t *res_j0 = x + i0;
    uint64_t c = (uint64_t)0U;
    {
      uint64_t a_i = n[(uint32_t)4U * (uint32_t)0U];
      uint64_t *res_i0 = res_j0 + (uint32_t)4U * (uint32_t)0U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, qj, c, res_i0);
      uint64_t a_i0 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
      uint64_t *res_i1 = res_j0 + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i0, qj, c, res_i1);
      uint64_t a_i1 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
      uint64_t *res_i2 = res_j0 + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i1, qj, c, res_i2);
      uint64_t a_i2 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
      uint64_t *res_i = res_j0 + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i2, qj, c, res_i);
    }
    KRML_MAYBE_FOR2(i,
      (uint32_t)4U,
      (uint32_t)6U,
      (uint32_t)1U,
      uint64_t a_i = n[i];
      uint64_t *res_i = res_j0 + i;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, qj, c, res_i););
    uint64_t r = c;
    uint64_t c1 = r;
    uint64_t *resb = x + (uint32_t)6U + i0;
    uint64_t res_j = x[(uint32_t)6U + i0];
    c0 = Lib_IntTypes_Intrinsics_add_carry_u64(c0, c1, res_j, resb););
  memcpy(res, x + (uint32_t)6U, (uint32_t)6U * sizeof (uint64_t));
  uint64_t c00 = c0;
  uint64_t tmp[6U] = { 0U };
  uint64_t c = (uint64_t)0U;
  {
    uint64_t t1 = res[(uint32_t)4U * (uint32_t)0U];
    uint64_t t20 = n[(uint32_t)4U * (uint32_t)0U];
    uint64_t *res_i0 = tmp + (uint32_t)4U * (uint32_t)0U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t1, t20, res_i0);
    uint64_t t10 = res[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t t21 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t *res_i1 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t10, t21, res_i1);
    uint64_t t11 = res[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t t22 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t *res_i2 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t11, t22, res_i2);
    uint64_t t12 = res[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t t2 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t *res_i = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t12, t2, res_i);
  }
  KRML_MAYBE_FOR2(i,
    (uint32_t)4U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t t1 = res[i];
    uint64_t t2 = n[i];
    uint64_t *res_i = tmp + i;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t1, t2, res_i););
  uint64_t c1 = c;
  uint64_t c2 = c00 - c1;
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *os = res;
    uint64_t x1 = (c2 & res[i]) | (~c2 & tmp[i]);
    os[i] = x1;);
}

static inline void qmont_reduction(uint64_t *res, uint64_t *x)
{
  uint64_t n[6U] = { 0U };
  p384_make_order(n);
  uint64_t c0 = (uint64_t)0U;
  KRML_MAYBE_FOR6(i0,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t qj = (uint64_t)7986114184663260229U * x[i0];
    uint64_t *res_j0 = x + i0;
    uint64_t c = (uint64_t)0U;
    {
      uint64_t a_i = n[(uint32_t)4U * (uint32_t)0U];
      uint64_t *res_i0 = res_j0 + (uint32_t)4U * (uint32_t)0U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, qj, c, res_i0);
      uint64_t a_i0 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
      uint64_t *res_i1 = res_j0 + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i0, qj, c, res_i1);
      uint64_t a_i1 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
      uint64_t *res_i2 = res_j0 + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i1, qj, c, res_i2);
      uint64_t a_i2 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
      uint64_t *res_i = res_j0 + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i2, qj, c, res_i);
    }
    KRML_MAYBE_FOR2(i,
      (uint32_t)4U,
      (uint32_t)6U,
      (uint32_t)1U,
      uint64_t a_i = n[i];
      uint64_t *res_i = res_j0 + i;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, qj, c, res_i););
    uint64_t r = c;
    uint64_t c1 = r;
    uint64_t *resb = x + (uint32_t)6U + i0;
    uint64_t res_j = x[(uint32_t)6U + i0];
    c0 = Lib_IntTypes_Intrinsics_add_carry_u64(c0, c1, res_j, resb););
  memcpy(res, x + (uint32_t)6U, (uint32_t)6U * sizeof (uint64_t));
  uint64_t c00 = c0;
  uint64_t tmp[6U] = { 0U };
  uint64_t c = (uint64_t)0U;
  {
    uint64_t t1 = res[(uint32_t)4U * (uint32_t)0U];
    uint64_t t20 = n[(uint32_t)4U * (uint32_t)0U];
    uint64_t *res_i0 = tmp + (uint32_t)4U * (uint32_t)0U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t1, t20, res_i0);
    uint64_t t10 = res[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t t21 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)1U];
    uint64_t *res_i1 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)1U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t10, t21, res_i1);
    uint64_t t11 = res[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t t22 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)2U];
    uint64_t *res_i2 = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)2U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t11, t22, res_i2);
    uint64_t t12 = res[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t t2 = n[(uint32_t)4U * (uint32_t)0U + (uint32_t)3U];
    uint64_t *res_i = tmp + (uint32_t)4U * (uint32_t)0U + (uint32_t)3U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t12, t2, res_i);
  }
  KRML_MAYBE_FOR2(i,
    (uint32_t)4U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t t1 = res[i];
    uint64_t t2 = n[i];
    uint64_t *res_i = tmp + i;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t1, t2, res_i););
  uint64_t c1 = c;
  uint64_t c2 = c00 - c1;
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *os = res;
    uint64_t x1 = (c2 & res[i]) | (~c2 & tmp[i]);
    os[i] = x1;);
}

static inline uint64_t bn_is_lt_prime_mask(uint64_t *f)
{
  uint64_t tmp[6U] = { 0U };
  p384_make_prime(tmp);
  uint64_t c = bn_sub(tmp, f, tmp);
  return (uint64_t)0U - c;
}

static inline void fadd(uint64_t *a, uint64_t *b, uint64_t *c)
{
  uint64_t n[6U] = { 0U };
  p384_make_prime(n);
  bn_add_mod(a, n, b, c);
}

static inline void fsub(uint64_t *a, uint64_t *b, uint64_t *c)
{
  uint64_t n[6U] = { 0U };
  p384_make_prime(n);
  bn_sub_mod(a, n, b, c);
}

static inline void fmul(uint64_t *a, uint64_t *b, uint64_t *c)
{
  uint64_t tmp[12U] = { 0U };
  bn_mul(tmp, b, c);
  fmont_reduction(a, tmp);
}

static inline void fsqr(uint64_t *a, uint64_t *b)
{
  uint64_t tmp[12U] = { 0U };
  bn_sqr(tmp, b);
  fmont_reduction(a, tmp);
}

static inline void from_mont(uint64_t *a, uint64_t *b)
{
  uint64_t tmp[12U] = { 0U };
  memcpy(tmp, b, (uint32_t)6U * sizeof (uint64_t));
  fmont_reduction(a, tmp);
}

static inline void to_mont(uint64_t *a, uint64_t *b)
{
  uint64_t r2modn[6U] = { 0U };
  p384_make_fmont_R2(r2modn);
  uint64_t tmp[12U] = { 0U };
  bn_mul(tmp, b, r2modn);
  fmont_reduction(a, tmp);
}

static inline void fexp_vartime(uint64_t *out, uint64_t *a, uint64_t *b)
{
  uint64_t table[192U] = { 0U };
  uint64_t tmp[6U] = { 0U };
  uint64_t *t0 = table;
  uint64_t *t1 = table + (uint32_t)6U;
  p384_make_fone(t0);
  memcpy(t1, a, (uint32_t)6U * sizeof (uint64_t));
  KRML_MAYBE_FOR15(i,
    (uint32_t)0U,
    (uint32_t)15U,
    (uint32_t)1U,
    uint64_t *t11 = table + (i + (uint32_t)1U) * (uint32_t)6U;
    fsqr(tmp, t11);
    memcpy(table + ((uint32_t)2U * i + (uint32_t)2U) * (uint32_t)6U,
      tmp,
      (uint32_t)6U * sizeof (uint64_t));
    uint64_t *t2 = table + ((uint32_t)2U * i + (uint32_t)2U) * (uint32_t)6U;
    fmul(tmp, a, t2);
    memcpy(table + ((uint32_t)2U * i + (uint32_t)3U) * (uint32_t)6U,
      tmp,
      (uint32_t)6U * sizeof (uint64_t)););
  uint32_t i0 = (uint32_t)380U;
  uint64_t bits_c = Hacl_Bignum_Lib_bn_get_bits_u64((uint32_t)6U, b, i0, (uint32_t)5U);
  uint32_t bits_l32 = (uint32_t)bits_c;
  const uint64_t *a_bits_l = table + bits_l32 * (uint32_t)6U;
  memcpy(out, (uint64_t *)a_bits_l, (uint32_t)6U * sizeof (uint64_t));
  uint64_t tmp0[6U] = { 0U };
  for (uint32_t i = (uint32_t)0U; i < (uint32_t)76U; i++)
  {
    KRML_MAYBE_FOR5(i1, (uint32_t)0U, (uint32_t)5U, (uint32_t)1U, fsqr(out, out););
    uint32_t k = (uint32_t)380U - (uint32_t)5U * i - (uint32_t)5U;
    uint64_t bits_l = Hacl_Bignum_Lib_bn_get_bits_u64((uint32_t)6U, b, k, (uint32_t)5U);
    uint32_t bits_l320 = (uint32_t)bits_l;
    const uint64_t *a_bits_l0 = table + bits_l320 * (uint32_t)6U;
    memcpy(tmp0, (uint64_t *)a_bits_l0, (uint32_t)6U * sizeof (uint64_t));
    fmul(out, out, tmp0);
  }
}

static inline void p384_finv(uint64_t *res, uint64_t *a)
{
  uint64_t b[6U] = { 0U };
  b[0U] = (uint64_t)0x00000000fffffffdU;
  b[1U] = (uint64_t)0xffffffff00000000U;
  b[2U] = (uint64_t)0xfffffffffffffffeU;
  b[3U] = (uint64_t)0xffffffffffffffffU;
  b[4U] = (uint64_t)0xffffffffffffffffU;
  b[5U] = (uint64_t)0xffffffffffffffffU;
  fexp_vartime(res, a, b);
}

static inline void p384_fsqrt(uint64_t *res, uint64_t *a)
{
  uint64_t b[6U] = { 0U };
  b[0U] = (uint64_t)0x0000000040000000U;
  b[1U] = (uint64_t)0xbfffffffc0000000U;
  b[2U] = (uint64_t)0xffffffffffffffffU;
  b[3U] = (uint64_t)0xffffffffffffffffU;
  b[4U] = (uint64_t)0xffffffffffffffffU;
  b[5U] = (uint64_t)0x3fffffffffffffffU;
  fexp_vartime(res, a, b);
}

static inline uint64_t load_qelem_conditional(uint64_t *a, uint8_t *b)
{
  bn_from_bytes_be(a, b);
  uint64_t tmp[6U] = { 0U };
  p384_make_order(tmp);
  uint64_t c = bn_sub(tmp, a, tmp);
  uint64_t is_lt_order = (uint64_t)0U - c;
  uint64_t bn_zero[6U] = { 0U };
  uint64_t res = bn_is_eq_mask(a, bn_zero);
  uint64_t is_eq_zero = res;
  uint64_t is_b_valid = is_lt_order & ~is_eq_zero;
  uint64_t oneq[6U] = { 0U };
  memset(oneq, 0U, (uint32_t)6U * sizeof (uint64_t));
  oneq[0U] = (uint64_t)1U;
  KRML_MAYBE_FOR6(i,
    (uint32_t)0U,
    (uint32_t)6U,
    (uint32_t)1U,
    uint64_t *os = a;
    uint64_t uu____0 = oneq[i];
    uint64_t x = uu____0 ^ (is_b_valid & (a[i] ^ uu____0));
    os[i] = x;);
  return is_b_valid;
}

static inline void qmod_short(uint64_t *a, uint64_t *b)
{
  uint64_t tmp[6U] = { 0U };
  p384_make_order(tmp);
  uint64_t c = bn_sub(tmp, b, tmp);
  bn_cmovznz(a, c, tmp, b);
}

static inline void qadd(uint64_t *a, uint64_t *b, uint64_t *c)
{
  uint64_t n[6U] = { 0U };
  p384_make_order(n);
  bn_add_mod(a, n, b, c);
}

static inline void qmul(uint64_t *a, uint64_t *b, uint64_t *c)
{
  uint64_t tmp[12U] = { 0U };
  bn_mul(tmp, b, c);
  qmont_reduction(a, tmp);
}

static inline void qsqr(uint64_t *a, uint64_t *b)
{
  uint64_t tmp[12U] = { 0U };
  bn_sqr(tmp, b);
  qmont_reduction(a, tmp);
}

static inline void from_qmont(uint64_t *a, uint64_t *b)
{
  uint64_t tmp[12U] = { 0U };
  memcpy(tmp, b, (uint32_t)6U * sizeof (uint64_t));
  qmont_reduction(a, tmp);
}

static inline void qexp_vartime(uint64_t *out, uint64_t *a, uint64_t *b)
{
  uint64_t table[192U] = { 0U };
  uint64_t tmp[6U] = { 0U };
  uint64_t *t0 = table;
  uint64_t *t1 = table + (uint32_t)6U;
  p384_make_qone(t0);
  memcpy(t1, a, (uint32_t)6U * sizeof (uint64_t));
  KRML_MAYBE_FOR15(i,
    (uint32_t)0U,
    (uint32_t)15U,
    (uint32_t)1U,
    uint64_t *t11 = table + (i + (uint32_t)1U) * (uint32_t)6U;
    qsqr(tmp, t11);
    memcpy(table + ((uint32_t)2U * i + (uint32_t)2U) * (uint32_t)6U,
      tmp,
      (uint32_t)6U * sizeof (uint64_t));
    uint64_t *t2 = table + ((uint32_t)2U * i + (uint32_t)2U) * (uint32_t)6U;
    qmul(tmp, a, t2);
    memcpy(table + ((uint32_t)2U * i + (uint32_t)3U) * (uint32_t)6U,
      tmp,
      (uint32_t)6U * sizeof (uint64_t)););
  uint32_t i0 = (uint32_t)380U;
  uint64_t bits_c = Hacl_Bignum_Lib_bn_get_bits_u64((uint32_t)6U, b, i0, (uint32_t)5U);
  uint32_t bits_l32 = (uint32_t)bits_c;
  const uint64_t *a_bits_l = table + bits_l32 * (uint32_t)6U;
  memcpy(out, (uint64_t *)a_bits_l, (uint32_t)6U * sizeof (uint64_t));
  uint64_t tmp0[6U] = { 0U };
  for (uint32_t i = (uint32_t)0U; i < (uint32_t)76U; i++)
  {
    KRML_MAYBE_FOR5(i1, (uint32_t)0U, (uint32_t)5U, (uint32_t)1U, qsqr(out, out););
    uint32_t k = (uint32_t)380U - (uint32_t)5U * i - (uint32_t)5U;
    uint64_t bits_l = Hacl_Bignum_Lib_bn_get_bits_u64((uint32_t)6U, b, k, (uint32_t)5U);
    uint32_t bits_l320 = (uint32_t)bits_l;
    const uint64_t *a_bits_l0 = table + bits_l320 * (uint32_t)6U;
    memcpy(tmp0, (uint64_t *)a_bits_l0, (uint32_t)6U * sizeof (uint64_t));
    qmul(out, out, tmp0);
  }
}

static inline void p384_qinv(uint64_t *res)
{
  uint64_t b[6U] = { 0U };
  b[0U] = (uint64_t)0xecec196accc52971U;
  b[1U] = (uint64_t)0x581a0db248b0a77aU;
  b[2U] = (uint64_t)0xc7634d81f4372ddfU;
  b[3U] = (uint64_t)0xffffffffffffffffU;
  b[4U] = (uint64_t)0xffffffffffffffffU;
  b[5U] = (uint64_t)0xffffffffffffffffU;
  uint64_t tmp[6U] = { 0U };
  qexp_vartime(res, tmp, b);
}

static inline void point_add(uint64_t *x, uint64_t *y, uint64_t *xy)
{
  uint64_t tmp[54U] = { 0U };
  uint64_t *t0 = tmp;
  uint64_t *t1 = tmp + (uint32_t)36U;
  uint64_t *x3 = t1;
  uint64_t *y3 = t1 + (uint32_t)6U;
  uint64_t *z3 = t1 + (uint32_t)12U;
  uint64_t *t01 = t0;
  uint64_t *t11 = t0 + (uint32_t)6U;
  uint64_t *t2 = t0 + (uint32_t)12U;
  uint64_t *t3 = t0 + (uint32_t)18U;
  uint64_t *t4 = t0 + (uint32_t)24U;
  uint64_t *t5 = t0 + (uint32_t)30U;
  uint64_t *x1 = x;
  uint64_t *y1 = x + (uint32_t)6U;
  uint64_t *z10 = x + (uint32_t)12U;
  uint64_t *x20 = y;
  uint64_t *y20 = y + (uint32_t)6U;
  uint64_t *z20 = y + (uint32_t)12U;
  fmul(t01, x1, x20);
  fmul(t11, y1, y20);
  fmul(t2, z10, z20);
  fadd(t3, x1, y1);
  fadd(t4, x20, y20);
  fmul(t3, t3, t4);
  fadd(t4, t01, t11);
  uint64_t *y10 = x + (uint32_t)6U;
  uint64_t *z11 = x + (uint32_t)12U;
  uint64_t *y2 = y + (uint32_t)6U;
  uint64_t *z21 = y + (uint32_t)12U;
  fsub(t3, t3, t4);
  fadd(t4, y10, z11);
  fadd(t5, y2, z21);
  fmul(t4, t4, t5);
  fadd(t5, t11, t2);
  fsub(t4, t4, t5);
  uint64_t *x10 = x;
  uint64_t *z1 = x + (uint32_t)12U;
  uint64_t *x2 = y;
  uint64_t *z2 = y + (uint32_t)12U;
  fadd(x3, x10, z1);
  fadd(y3, x2, z2);
  fmul(x3, x3, y3);
  fadd(y3, t01, t2);
  fsub(y3, x3, y3);
  uint64_t b_coeff[6U] = { 0U };
  p384_make_b_coeff(b_coeff);
  fmul(z3, b_coeff, t2);
  fsub(x3, y3, z3);
  fadd(z3, x3, x3);
  fadd(x3, x3, z3);
  fsub(z3, t11, x3);
  fadd(x3, t11, x3);
  uint64_t b_coeff0[6U] = { 0U };
  p384_make_b_coeff(b_coeff0);
  fmul(y3, b_coeff0, y3);
  fadd(t11, t2, t2);
  fadd(t2, t11, t2);
  fsub(y3, y3, t2);
  fsub(y3, y3, t01);
  fadd(t11, y3, y3);
  fadd(y3, t11, y3);
  fadd(t11, t01, t01);
  fadd(t01, t11, t01);
  fsub(t01, t01, t2);
  fmul(t11, t4, y3);
  fmul(t2, t01, y3);
  fmul(y3, x3, z3);
  fadd(y3, y3, t2);
  fmul(x3, t3, x3);
  fsub(x3, x3, t11);
  fmul(z3, t4, z3);
  fmul(t11, t3, t01);
  fadd(z3, z3, t11);
  memcpy(xy, t1, (uint32_t)18U * sizeof (uint64_t));
}

static inline void point_double(uint64_t *x, uint64_t *xx)
{
  uint64_t tmp[30U] = { 0U };
  uint64_t *x1 = x;
  uint64_t *z = x + (uint32_t)12U;
  uint64_t *x3 = xx;
  uint64_t *y3 = xx + (uint32_t)6U;
  uint64_t *z3 = xx + (uint32_t)12U;
  uint64_t *t0 = tmp;
  uint64_t *t1 = tmp + (uint32_t)6U;
  uint64_t *t2 = tmp + (uint32_t)12U;
  uint64_t *t3 = tmp + (uint32_t)18U;
  uint64_t *t4 = tmp + (uint32_t)24U;
  uint64_t *x2 = x;
  uint64_t *y = x + (uint32_t)6U;
  uint64_t *z1 = x + (uint32_t)12U;
  fsqr(t0, x2);
  fsqr(t1, y);
  fsqr(t2, z1);
  fmul(t3, x2, y);
  fadd(t3, t3, t3);
  fmul(t4, y, z1);
  fmul(z3, x1, z);
  fadd(z3, z3, z3);
  uint64_t b_coeff[6U] = { 0U };
  p384_make_b_coeff(b_coeff);
  fmul(y3, b_coeff, t2);
  fsub(y3, y3, z3);
  fadd(x3, y3, y3);
  fadd(y3, x3, y3);
  fsub(x3, t1, y3);
  fadd(y3, t1, y3);
  fmul(y3, x3, y3);
  fmul(x3, x3, t3);
  fadd(t3, t2, t2);
  fadd(t2, t2, t3);
  uint64_t b_coeff0[6U] = { 0U };
  p384_make_b_coeff(b_coeff0);
  fmul(z3, b_coeff0, z3);
  fsub(z3, z3, t2);
  fsub(z3, z3, t0);
  fadd(t3, z3, z3);
  fadd(z3, z3, t3);
  fadd(t3, t0, t0);
  fadd(t0, t3, t0);
  fsub(t0, t0, t2);
  fmul(t0, t0, z3);
  fadd(y3, y3, t0);
  fadd(t0, t4, t4);
  fmul(z3, t0, z3);
  fsub(x3, x3, z3);
  fmul(z3, t0, t1);
  fadd(z3, z3, z3);
  fadd(z3, z3, z3);
}

static inline void point_zero(uint64_t *one)
{
  uint64_t *x = one;
  uint64_t *y = one + (uint32_t)6U;
  uint64_t *z = one + (uint32_t)12U;
  p384_make_fzero(x);
  p384_make_fone(y);
  p384_make_fzero(z);
}

static inline void point_mul(uint64_t *res, uint64_t *scalar, uint64_t *p)
{
  uint64_t table[288U] = { 0U };
  uint64_t tmp[18U] = { 0U };
  uint64_t *t0 = table;
  uint64_t *t1 = table + (uint32_t)18U;
  point_zero(t0);
  memcpy(t1, p, (uint32_t)18U * sizeof (uint64_t));
  KRML_MAYBE_FOR7(i,
    (uint32_t)0U,
    (uint32_t)7U,
    (uint32_t)1U,
    uint64_t *t11 = table + (i + (uint32_t)1U) * (uint32_t)18U;
    point_double(t11, tmp);
    memcpy(table + ((uint32_t)2U * i + (uint32_t)2U) * (uint32_t)18U,
      tmp,
      (uint32_t)18U * sizeof (uint64_t));
    uint64_t *t2 = table + ((uint32_t)2U * i + (uint32_t)2U) * (uint32_t)18U;
    point_add(p, t2, tmp);
    memcpy(table + ((uint32_t)2U * i + (uint32_t)3U) * (uint32_t)18U,
      tmp,
      (uint32_t)18U * sizeof (uint64_t)););
  point_zero(res);
  uint64_t tmp0[18U] = { 0U };
  for (uint32_t i0 = (uint32_t)0U; i0 < (uint32_t)96U; i0++)
  {
    KRML_MAYBE_FOR4(i, (uint32_t)0U, (uint32_t)4U, (uint32_t)1U, point_double(res, res););
    uint32_t k = (uint32_t)384U - (uint32_t)4U * i0 - (uint32_t)4U;
    uint64_t bits_l = Hacl_Bignum_Lib_bn_get_bits_u64((uint32_t)6U, scalar, k, (uint32_t)4U);
    memcpy(tmp0, (uint64_t *)table, (uint32_t)18U * sizeof (uint64_t));
    KRML_MAYBE_FOR15(i1,
      (uint32_t)0U,
      (uint32_t)15U,
      (uint32_t)1U,
      uint64_t c = FStar_UInt64_eq_mask(bits_l, (uint64_t)(i1 + (uint32_t)1U));
      const uint64_t *res_j = table + (i1 + (uint32_t)1U) * (uint32_t)18U;
      for (uint32_t i = (uint32_t)0U; i < (uint32_t)18U; i++)
      {
        uint64_t *os = tmp0;
        uint64_t x = (c & res_j[i]) | (~c & tmp0[i]);
        os[i] = x;
      });
    point_add(res, tmp0, res);
  }
}

static inline void point_mul_g(uint64_t *res, uint64_t *scalar)
{
  uint64_t g[18U] = { 0U };
  uint64_t *x = g;
  uint64_t *y = g + (uint32_t)6U;
  uint64_t *z = g + (uint32_t)12U;
  p384_make_g_x(x);
  p384_make_g_y(y);
  p384_make_fone(z);
  point_mul(res, scalar, g);
}

static inline void
point_mul_double_g(uint64_t *res, uint64_t *scalar1, uint64_t *scalar2, uint64_t *p)
{
  uint64_t tmp[18U] = { 0U };
  point_mul_g(tmp, scalar1);
  point_mul(res, scalar2, p);
  point_add(res, tmp, res);
}

static inline bool
ecdsa_sign_msg_as_qelem(
  uint8_t *signature,
  uint64_t *m_q,
  uint8_t *private_key,
  uint8_t *nonce
)
{
  uint64_t rsdk_q[24U] = { 0U };
  uint64_t *r_q = rsdk_q;
  uint64_t *s_q = rsdk_q + (uint32_t)6U;
  uint64_t *d_a = rsdk_q + (uint32_t)12U;
  uint64_t *k_q = rsdk_q + (uint32_t)18U;
  uint64_t is_sk_valid = load_qelem_conditional(d_a, private_key);
  uint64_t is_nonce_valid = load_qelem_conditional(k_q, nonce);
  uint64_t are_sk_nonce_valid = is_sk_valid & is_nonce_valid;
  uint64_t p[18U] = { 0U };
  point_mul_g(p, k_q);
  uint64_t zinv[6U] = { 0U };
  uint64_t *px = p;
  uint64_t *pz = p + (uint32_t)12U;
  p384_finv(zinv, pz);
  fmul(r_q, px, zinv);
  from_mont(r_q, r_q);
  qmod_short(r_q, r_q);
  uint64_t kinv[6U] = { 0U };
  p384_qinv(kinv);
  qmul(s_q, r_q, d_a);
  from_qmont(m_q, m_q);
  qadd(s_q, m_q, s_q);
  qmul(s_q, kinv, s_q);
  bn_to_bytes_be(signature, r_q);
  bn_to_bytes_be(signature + (uint32_t)48U, s_q);
  uint64_t bn_zero0[6U] = { 0U };
  uint64_t res = bn_is_eq_mask(r_q, bn_zero0);
  uint64_t is_r_zero = res;
  uint64_t bn_zero[6U] = { 0U };
  uint64_t res0 = bn_is_eq_mask(s_q, bn_zero);
  uint64_t is_s_zero = res0;
  uint64_t m = are_sk_nonce_valid & (~is_r_zero & ~is_s_zero);
  bool res1 = m == (uint64_t)0xFFFFFFFFFFFFFFFFU;
  return res1;
}

static inline bool
ecdsa_verify_msg_as_qelem(
  uint64_t *m_q,
  uint8_t *public_key,
  uint8_t *signature_r,
  uint8_t *signature_s
)
{
  uint64_t tmp[42U] = { 0U };
  uint64_t *pk = tmp;
  uint64_t *r_q = tmp + (uint32_t)18U;
  uint64_t *s_q = tmp + (uint32_t)24U;
  uint64_t *u1 = tmp + (uint32_t)30U;
  uint64_t *u2 = tmp + (uint32_t)36U;
  uint64_t p_aff[12U] = { 0U };
  uint8_t *p_x = public_key;
  uint8_t *p_y = public_key + (uint32_t)48U;
  uint64_t *bn_p_x = p_aff;
  uint64_t *bn_p_y = p_aff + (uint32_t)6U;
  bn_from_bytes_be(bn_p_x, p_x);
  bn_from_bytes_be(bn_p_y, p_y);
  uint64_t *px0 = p_aff;
  uint64_t *py0 = p_aff + (uint32_t)6U;
  uint64_t lessX = bn_is_lt_prime_mask(px0);
  uint64_t lessY = bn_is_lt_prime_mask(py0);
  uint64_t res0 = lessX & lessY;
  bool is_xy_valid = res0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
  bool res;
  if (!is_xy_valid)
  {
    res = false;
  }
  else
  {
    uint64_t rp[6U] = { 0U };
    uint64_t tx[6U] = { 0U };
    uint64_t ty[6U] = { 0U };
    uint64_t *px = p_aff;
    uint64_t *py = p_aff + (uint32_t)6U;
    to_mont(tx, px);
    to_mont(ty, py);
    uint64_t tmp1[6U] = { 0U };
    fsqr(rp, tx);
    fmul(rp, rp, tx);
    p384_make_a_coeff(tmp1);
    fmul(tmp1, tmp1, tx);
    fadd(rp, tmp1, rp);
    p384_make_b_coeff(tmp1);
    fadd(rp, tmp1, rp);
    fsqr(ty, ty);
    uint64_t r = bn_is_eq_mask(ty, rp);
    uint64_t r0 = r;
    bool r1 = r0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
    res = r1;
  }
  if (res)
  {
    uint64_t *px = p_aff;
    uint64_t *py = p_aff + (uint32_t)6U;
    uint64_t *rx = pk;
    uint64_t *ry = pk + (uint32_t)6U;
    uint64_t *rz = pk + (uint32_t)12U;
    to_mont(rx, px);
    to_mont(ry, py);
    p384_make_fone(rz);
  }
  bool is_pk_valid = res;
  bn_from_bytes_be(r_q, signature_r);
  bn_from_bytes_be(s_q, signature_s);
  uint64_t tmp10[6U] = { 0U };
  p384_make_order(tmp10);
  uint64_t c = bn_sub(tmp10, r_q, tmp10);
  uint64_t is_lt_order = (uint64_t)0U - c;
  uint64_t bn_zero0[6U] = { 0U };
  uint64_t res1 = bn_is_eq_mask(r_q, bn_zero0);
  uint64_t is_eq_zero = res1;
  uint64_t is_r_valid = is_lt_order & ~is_eq_zero;
  uint64_t tmp11[6U] = { 0U };
  p384_make_order(tmp11);
  uint64_t c0 = bn_sub(tmp11, s_q, tmp11);
  uint64_t is_lt_order0 = (uint64_t)0U - c0;
  uint64_t bn_zero1[6U] = { 0U };
  uint64_t res2 = bn_is_eq_mask(s_q, bn_zero1);
  uint64_t is_eq_zero0 = res2;
  uint64_t is_s_valid = is_lt_order0 & ~is_eq_zero0;
  bool
  is_rs_valid =
    is_r_valid
    == (uint64_t)0xFFFFFFFFFFFFFFFFU
    && is_s_valid == (uint64_t)0xFFFFFFFFFFFFFFFFU;
  if (!(is_pk_valid && is_rs_valid))
  {
    return false;
  }
  uint64_t sinv[6U] = { 0U };
  p384_qinv(sinv);
  uint64_t tmp1[6U] = { 0U };
  from_qmont(tmp1, m_q);
  qmul(u1, sinv, tmp1);
  uint64_t tmp12[6U] = { 0U };
  from_qmont(tmp12, r_q);
  qmul(u2, sinv, tmp12);
  uint64_t res3[18U] = { 0U };
  point_mul_double_g(res3, u1, u2, pk);
  uint64_t *pz0 = res3 + (uint32_t)12U;
  uint64_t bn_zero[6U] = { 0U };
  uint64_t res10 = bn_is_eq_mask(pz0, bn_zero);
  uint64_t m = res10;
  if (m == (uint64_t)0xFFFFFFFFFFFFFFFFU)
  {
    return false;
  }
  uint64_t x[6U] = { 0U };
  uint64_t zinv[6U] = { 0U };
  uint64_t *px = res3;
  uint64_t *pz = res3 + (uint32_t)12U;
  p384_finv(zinv, pz);
  fmul(x, px, zinv);
  from_mont(x, x);
  qmod_short(x, x);
  uint64_t m0 = bn_is_eq_mask(x, r_q);
  bool res11 = m0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
  return res11;
}


/*******************************************************************************

 Verified C library for ECDSA and ECDH functions over the P-384 NIST curve.

 This module implements signing and verification, key validation, conversions
 between various point representations, and ECDH key agreement.

*******************************************************************************/

/*****************/
/* ECDSA signing */
/*****************/

/*
  As per the standard, a hash function *shall* be used. Therefore, we recommend
  using one of the three combined hash-and-sign variants.
*/

/**
Create an ECDSA signature using SHA2-256.

  The function returns `true` for successful creation of an ECDSA signature and `false` otherwise.

  The outparam `signature` (R || S) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The arguments `private_key` and `nonce` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `private_key` and `nonce` are valid:
    • 0 < `private_key` < the order of the curve
    • 0 < `nonce` < the order of the curve
*/
bool
Hacl_P384_ecdsa_sign_p384_sha2(
  uint8_t *signature,
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *private_key,
  uint8_t *nonce
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[32U] = { 0U };
  Hacl_Streaming_SHA2_hash_256(msg, msg_len, mHash);
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_sign_msg_as_qelem(signature, m_q, private_key, nonce);
  return res;
}

/**
Create an ECDSA signature using SHA2-384.

  The function returns `true` for successful creation of an ECDSA signature and `false` otherwise.

  The outparam `signature` (R || S) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The arguments `private_key` and `nonce` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `private_key` and `nonce` are valid:
    • 0 < `private_key` < the order of the curve
    • 0 < `nonce` < the order of the curve
*/
bool
Hacl_P384_ecdsa_sign_p384_sha384(
  uint8_t *signature,
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *private_key,
  uint8_t *nonce
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[48U] = { 0U };
  Hacl_Streaming_SHA2_hash_384(msg, msg_len, mHash);
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_sign_msg_as_qelem(signature, m_q, private_key, nonce);
  return res;
}

/**
Create an ECDSA signature using SHA2-512.

  The function returns `true` for successful creation of an ECDSA signature and `false` otherwise.

  The outparam `signature` (R || S) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The arguments `private_key` and `nonce` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `private_key` and `nonce` are valid:
    • 0 < `private_key` < the order of the curve
    • 0 < `nonce` < the order of the curve
*/
bool
Hacl_P384_ecdsa_sign_p384_sha512(
  uint8_t *signature,
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *private_key,
  uint8_t *nonce
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[64U] = { 0U };
  Hacl_Streaming_SHA2_hash_512(msg, msg_len, mHash);
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_sign_msg_as_qelem(signature, m_q, private_key, nonce);
  return res;
}

/**
Create an ECDSA signature WITHOUT hashing first.

  This function is intended to receive a hash of the input.
  For convenience, we recommend using one of the hash-and-sign combined functions above.

  The argument `msg` MUST be at least 48 bytes (i.e. `msg_len >= 48`).

  NOTE: The equivalent functions in OpenSSL and Fiat-Crypto both accept inputs
  smaller than 48 bytes. These libraries left-pad the input with enough zeroes to
  reach the minimum 48 byte size. Clients who need behavior identical to OpenSSL
  need to perform the left-padding themselves.

  The function returns `true` for successful creation of an ECDSA signature and `false` otherwise.

  The outparam `signature` (R || S) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The arguments `private_key` and `nonce` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `private_key` and `nonce` are valid values:
    • 0 < `private_key` < the order of the curve
    • 0 < `nonce` < the order of the curve
*/
bool
Hacl_P384_ecdsa_sign_p384_without_hash(
  uint8_t *signature,
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *private_key,
  uint8_t *nonce
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[48U] = { 0U };
  memcpy(mHash, msg, (uint32_t)48U * sizeof (uint8_t));
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_sign_msg_as_qelem(signature, m_q, private_key, nonce);
  return res;
}


/**********************/
/* ECDSA verification */
/**********************/

/**
Verify an ECDSA signature using SHA2-256.

  The function returns `true` if the signature is valid and `false` otherwise.

  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The argument `public_key` (x || y) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The arguments `signature_r` and `signature_s` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `public_key` is valid
*/
bool
Hacl_P384_ecdsa_verif_p384_sha2(
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *public_key,
  uint8_t *signature_r,
  uint8_t *signature_s
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[32U] = { 0U };
  Hacl_Streaming_SHA2_hash_256(msg, msg_len, mHash);
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_verify_msg_as_qelem(m_q, public_key, signature_r, signature_s);
  return res;
}

/**
Verify an ECDSA signature using SHA2-384.

  The function returns `true` if the signature is valid and `false` otherwise.

  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The argument `public_key` (x || y) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The arguments `signature_r` and `signature_s` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `public_key` is valid
*/
bool
Hacl_P384_ecdsa_verif_p384_sha384(
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *public_key,
  uint8_t *signature_r,
  uint8_t *signature_s
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[48U] = { 0U };
  Hacl_Streaming_SHA2_hash_384(msg, msg_len, mHash);
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_verify_msg_as_qelem(m_q, public_key, signature_r, signature_s);
  return res;
}

/**
Verify an ECDSA signature using SHA2-512.

  The function returns `true` if the signature is valid and `false` otherwise.

  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The argument `public_key` (x || y) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The arguments `signature_r` and `signature_s` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `public_key` is valid
*/
bool
Hacl_P384_ecdsa_verif_p384_sha512(
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *public_key,
  uint8_t *signature_r,
  uint8_t *signature_s
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[64U] = { 0U };
  Hacl_Streaming_SHA2_hash_512(msg, msg_len, mHash);
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_verify_msg_as_qelem(m_q, public_key, signature_r, signature_s);
  return res;
}

/**
Verify an ECDSA signature WITHOUT hashing first.

  This function is intended to receive a hash of the input.
  For convenience, we recommend using one of the hash-and-verify combined functions above.

  The argument `msg` MUST be at least 48 bytes (i.e. `msg_len >= 48`).

  The function returns `true` if the signature is valid and `false` otherwise.

  The argument `msg` points to `msg_len` bytes of valid memory, i.e., uint8_t[msg_len].
  The argument `public_key` (x || y) points to 96 bytes of valid memory, i.e., uint8_t[96].
  The arguments `signature_r` and `signature_s` point to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `public_key` is valid
*/
bool
Hacl_P384_ecdsa_verif_without_hash(
  uint32_t msg_len,
  uint8_t *msg,
  uint8_t *public_key,
  uint8_t *signature_r,
  uint8_t *signature_s
)
{
  uint64_t m_q[6U] = { 0U };
  uint8_t mHash[48U] = { 0U };
  memcpy(mHash, msg, (uint32_t)48U * sizeof (uint8_t));
  KRML_HOST_IGNORE(msg_len);
  uint8_t *mHash48 = mHash;
  bn_from_bytes_be(m_q, mHash48);
  qmod_short(m_q, m_q);
  bool res = ecdsa_verify_msg_as_qelem(m_q, public_key, signature_r, signature_s);
  return res;
}


/******************/
/* Key validation */
/******************/

/**
Public key validation.

  The function returns `true` if a public key is valid and `false` otherwise.

  The argument `public_key` points to 96 bytes of valid memory, i.e., uint8_t[96].

  The public key (x || y) is valid (with respect to SP 800-56A):
    • the public key is not the “point at infinity”, represented as O.
    • the affine x and y coordinates of the point represented by the public key are
      in the range [0, p – 1] where p is the prime defining the finite field.
    • y^2 = x^3 + ax + b where a and b are the coefficients of the curve equation.
  The last extract is taken from: https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
*/
bool Hacl_P384_validate_public_key(uint8_t *public_key)
{
  uint64_t point_jac[18U] = { 0U };
  uint64_t p_aff[12U] = { 0U };
  uint8_t *p_x = public_key;
  uint8_t *p_y = public_key + (uint32_t)48U;
  uint64_t *bn_p_x = p_aff;
  uint64_t *bn_p_y = p_aff + (uint32_t)6U;
  bn_from_bytes_be(bn_p_x, p_x);
  bn_from_bytes_be(bn_p_y, p_y);
  uint64_t *px0 = p_aff;
  uint64_t *py0 = p_aff + (uint32_t)6U;
  uint64_t lessX = bn_is_lt_prime_mask(px0);
  uint64_t lessY = bn_is_lt_prime_mask(py0);
  uint64_t res0 = lessX & lessY;
  bool is_xy_valid = res0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
  bool res;
  if (!is_xy_valid)
  {
    res = false;
  }
  else
  {
    uint64_t rp[6U] = { 0U };
    uint64_t tx[6U] = { 0U };
    uint64_t ty[6U] = { 0U };
    uint64_t *px = p_aff;
    uint64_t *py = p_aff + (uint32_t)6U;
    to_mont(tx, px);
    to_mont(ty, py);
    uint64_t tmp[6U] = { 0U };
    fsqr(rp, tx);
    fmul(rp, rp, tx);
    p384_make_a_coeff(tmp);
    fmul(tmp, tmp, tx);
    fadd(rp, tmp, rp);
    p384_make_b_coeff(tmp);
    fadd(rp, tmp, rp);
    fsqr(ty, ty);
    uint64_t r = bn_is_eq_mask(ty, rp);
    uint64_t r0 = r;
    bool r1 = r0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
    res = r1;
  }
  if (res)
  {
    uint64_t *px = p_aff;
    uint64_t *py = p_aff + (uint32_t)6U;
    uint64_t *rx = point_jac;
    uint64_t *ry = point_jac + (uint32_t)6U;
    uint64_t *rz = point_jac + (uint32_t)12U;
    to_mont(rx, px);
    to_mont(ry, py);
    p384_make_fone(rz);
  }
  bool res1 = res;
  return res1;
}

/**
Private key validation.

  The function returns `true` if a private key is valid and `false` otherwise.

  The argument `private_key` points to 48 bytes of valid memory, i.e., uint8_t[48].

  The private key is valid:
    • 0 < `private_key` < the order of the curve
*/
bool Hacl_P384_validate_private_key(uint8_t *private_key)
{
  uint64_t bn_sk[6U] = { 0U };
  bn_from_bytes_be(bn_sk, private_key);
  uint64_t tmp[6U] = { 0U };
  p384_make_order(tmp);
  uint64_t c = bn_sub(tmp, bn_sk, tmp);
  uint64_t is_lt_order = (uint64_t)0U - c;
  uint64_t bn_zero[6U] = { 0U };
  uint64_t res = bn_is_eq_mask(bn_sk, bn_zero);
  uint64_t is_eq_zero = res;
  uint64_t res0 = is_lt_order & ~is_eq_zero;
  return res0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
}

/*******************************************************************************
  Parsing and Serializing public keys.

  A public key is a point (x, y) on the P-384 NIST curve.

  The point can be represented in the following three ways.
    • raw          = [ x || y ], 96 bytes
    • uncompressed = [ 0x04 || x || y ], 97 bytes
    • compressed   = [ (0x02 for even `y` and 0x03 for odd `y`) || x ], 33 bytes

*******************************************************************************/


/**
Convert a public key from uncompressed to its raw form.

  The function returns `true` for successful conversion of a public key and `false` otherwise.

  The outparam `pk_raw` points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `pk` points to 97 bytes of valid memory, i.e., uint8_t[97].

  The function DOESN'T check whether (x, y) is a valid point.
*/
bool Hacl_P384_uncompressed_to_raw(uint8_t *pk, uint8_t *pk_raw)
{
  uint8_t pk0 = pk[0U];
  if (pk0 != (uint8_t)0x04U)
  {
    return false;
  }
  memcpy(pk_raw, pk + (uint32_t)1U, (uint32_t)96U * sizeof (uint8_t));
  return true;
}

/**
Convert a public key from compressed to its raw form.

  The function returns `true` for successful conversion of a public key and `false` otherwise.

  The outparam `pk_raw` points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `pk` points to 33 bytes of valid memory, i.e., uint8_t[33].

  The function also checks whether (x, y) is a valid point.
*/
bool Hacl_P384_compressed_to_raw(uint8_t *pk, uint8_t *pk_raw)
{
  uint64_t xa[6U] = { 0U };
  uint64_t ya[6U] = { 0U };
  uint8_t *pk_xb = pk + (uint32_t)1U;
  uint8_t s0 = pk[0U];
  uint8_t s01 = s0;
  bool b;
  if (!(s01 == (uint8_t)0x02U || s01 == (uint8_t)0x03U))
  {
    b = false;
  }
  else
  {
    uint8_t *xb = pk + (uint32_t)1U;
    bn_from_bytes_be(xa, xb);
    uint64_t is_x_valid = bn_is_lt_prime_mask(xa);
    bool is_x_valid1 = is_x_valid == (uint64_t)0xFFFFFFFFFFFFFFFFU;
    bool is_y_odd = s01 == (uint8_t)0x03U;
    if (!is_x_valid1)
    {
      b = false;
    }
    else
    {
      uint64_t y2M[6U] = { 0U };
      uint64_t xM[6U] = { 0U };
      uint64_t yM[6U] = { 0U };
      to_mont(xM, xa);
      uint64_t tmp[6U] = { 0U };
      fsqr(y2M, xM);
      fmul(y2M, y2M, xM);
      p384_make_a_coeff(tmp);
      fmul(tmp, tmp, xM);
      fadd(y2M, tmp, y2M);
      p384_make_b_coeff(tmp);
      fadd(y2M, tmp, y2M);
      p384_fsqrt(yM, y2M);
      from_mont(ya, yM);
      fsqr(yM, yM);
      uint64_t r = bn_is_eq_mask(yM, y2M);
      uint64_t r0 = r;
      bool is_y_valid = r0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
      bool is_y_valid0 = is_y_valid;
      if (!is_y_valid0)
      {
        b = false;
      }
      else
      {
        uint64_t is_y_odd1 = ya[0U] & (uint64_t)1U;
        bool is_y_odd2 = is_y_odd1 == (uint64_t)1U;
        uint64_t zero[6U] = { 0U };
        if (is_y_odd2 != is_y_odd)
        {
          fsub(ya, zero, ya);
        }
        b = true;
      }
    }
  }
  if (b)
  {
    memcpy(pk_raw, pk_xb, (uint32_t)48U * sizeof (uint8_t));
    bn_to_bytes_be(pk_raw + (uint32_t)48U, ya);
  }
  return b;
}

/**
Convert a public key from raw to its uncompressed form.

  The outparam `pk` points to 97 bytes of valid memory, i.e., uint8_t[97].
  The argument `pk_raw` points to 96 bytes of valid memory, i.e., uint8_t[96].

  The function DOESN'T check whether (x, y) is a valid point.
*/
void Hacl_P384_raw_to_uncompressed(uint8_t *pk_raw, uint8_t *pk)
{
  pk[0U] = (uint8_t)0x04U;
  memcpy(pk + (uint32_t)1U, pk_raw, (uint32_t)96U * sizeof (uint8_t));
}

/**
Convert a public key from raw to its compressed form.

  The outparam `pk` points to 33 bytes of valid memory, i.e., uint8_t[33].
  The argument `pk_raw` points to 96 bytes of valid memory, i.e., uint8_t[96].

  The function DOESN'T check whether (x, y) is a valid point.
*/
void Hacl_P384_raw_to_compressed(uint8_t *pk_raw, uint8_t *pk)
{
  uint8_t *pk_x = pk_raw;
  uint8_t *pk_y = pk_raw + (uint32_t)48U;
  uint64_t bn_f[6U] = { 0U };
  bn_from_bytes_be(bn_f, pk_y);
  uint64_t is_odd_f = bn_f[0U] & (uint64_t)1U;
  pk[0U] = (uint8_t)is_odd_f + (uint8_t)0x02U;
  memcpy(pk + (uint32_t)1U, pk_x, (uint32_t)48U * sizeof (uint8_t));
}


/******************/
/* ECDH agreement */
/******************/

/**
Compute the public key from the private key.

  The function returns `true` if a private key is valid and `false` otherwise.

  The outparam `public_key`  points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `private_key` points to 48 bytes of valid memory, i.e., uint8_t[48].

  The private key is valid:
    • 0 < `private_key` < the order of the curve.
*/
bool Hacl_P384_dh_initiator(uint8_t *public_key, uint8_t *private_key)
{
  uint64_t tmp[24U] = { 0U };
  uint64_t *sk = tmp;
  uint64_t *pk = tmp + (uint32_t)6U;
  uint64_t is_sk_valid = load_qelem_conditional(sk, private_key);
  point_mul_g(pk, sk);
  uint64_t aff_p[12U] = { 0U };
  uint64_t zinv[6U] = { 0U };
  uint64_t *px = pk;
  uint64_t *py0 = pk + (uint32_t)6U;
  uint64_t *pz = pk + (uint32_t)12U;
  uint64_t *x = aff_p;
  uint64_t *y = aff_p + (uint32_t)6U;
  p384_finv(zinv, pz);
  fmul(x, px, zinv);
  fmul(y, py0, zinv);
  from_mont(x, x);
  from_mont(y, y);
  uint64_t *px0 = aff_p;
  uint64_t *py = aff_p + (uint32_t)6U;
  bn_to_bytes_be(public_key, px0);
  bn_to_bytes_be(public_key + (uint32_t)48U, py);
  return is_sk_valid == (uint64_t)0xFFFFFFFFFFFFFFFFU;
}

/**
Execute the diffie-hellmann key exchange.

  The function returns `true` for successful creation of an ECDH shared secret and
  `false` otherwise.

  The outparam `shared_secret` points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `their_pubkey` points to 96 bytes of valid memory, i.e., uint8_t[96].
  The argument `private_key` points to 48 bytes of valid memory, i.e., uint8_t[48].

  The function also checks whether `private_key` and `their_pubkey` are valid.
*/
bool
Hacl_P384_dh_responder(uint8_t *shared_secret, uint8_t *their_pubkey, uint8_t *private_key)
{
  uint64_t tmp[192U] = { 0U };
  uint64_t *sk = tmp;
  uint64_t *pk = tmp + (uint32_t)6U;
  uint64_t p_aff[12U] = { 0U };
  uint8_t *p_x = their_pubkey;
  uint8_t *p_y = their_pubkey + (uint32_t)48U;
  uint64_t *bn_p_x = p_aff;
  uint64_t *bn_p_y = p_aff + (uint32_t)6U;
  bn_from_bytes_be(bn_p_x, p_x);
  bn_from_bytes_be(bn_p_y, p_y);
  uint64_t *px0 = p_aff;
  uint64_t *py0 = p_aff + (uint32_t)6U;
  uint64_t lessX = bn_is_lt_prime_mask(px0);
  uint64_t lessY = bn_is_lt_prime_mask(py0);
  uint64_t res0 = lessX & lessY;
  bool is_xy_valid = res0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
  bool res;
  if (!is_xy_valid)
  {
    res = false;
  }
  else
  {
    uint64_t rp[6U] = { 0U };
    uint64_t tx[6U] = { 0U };
    uint64_t ty[6U] = { 0U };
    uint64_t *px = p_aff;
    uint64_t *py = p_aff + (uint32_t)6U;
    to_mont(tx, px);
    to_mont(ty, py);
    uint64_t tmp1[6U] = { 0U };
    fsqr(rp, tx);
    fmul(rp, rp, tx);
    p384_make_a_coeff(tmp1);
    fmul(tmp1, tmp1, tx);
    fadd(rp, tmp1, rp);
    p384_make_b_coeff(tmp1);
    fadd(rp, tmp1, rp);
    fsqr(ty, ty);
    uint64_t r = bn_is_eq_mask(ty, rp);
    uint64_t r0 = r;
    bool r1 = r0 == (uint64_t)0xFFFFFFFFFFFFFFFFU;
    res = r1;
  }
  if (res)
  {
    uint64_t *px = p_aff;
    uint64_t *py = p_aff + (uint32_t)6U;
    uint64_t *rx = pk;
    uint64_t *ry = pk + (uint32_t)6U;
    uint64_t *rz = pk + (uint32_t)12U;
    to_mont(rx, px);
    to_mont(ry, py);
    p384_make_fone(rz);
  }
  bool is_pk_valid = res;
  uint64_t is_sk_valid = load_qelem_conditional(sk, private_key);
  uint64_t ss_proj[18U] = { 0U };
  if (is_pk_valid)
  {
    point_mul(ss_proj, sk, pk);
    uint64_t aff_p[12U] = { 0U };
    uint64_t zinv[6U] = { 0U };
    uint64_t *px = ss_proj;
    uint64_t *py1 = ss_proj + (uint32_t)6U;
    uint64_t *pz = ss_proj + (uint32_t)12U;
    uint64_t *x = aff_p;
    uint64_t *y = aff_p + (uint32_t)6U;
    p384_finv(zinv, pz);
    fmul(x, px, zinv);
    fmul(y, py1, zinv);
    from_mont(x, x);
    from_mont(y, y);
    uint64_t *px1 = aff_p;
    uint64_t *py = aff_p + (uint32_t)6U;
    bn_to_bytes_be(shared_secret, px1);
    bn_to_bytes_be(shared_secret + (uint32_t)48U, py);
  }
  return is_sk_valid == (uint64_t)0xFFFFFFFFFFFFFFFFU && is_pk_valid;
}

