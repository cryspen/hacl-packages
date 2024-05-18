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


#ifndef __internal_Hacl_Bignum_Base_H
#define __internal_Hacl_Bignum_Base_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"

#include "internal/Hacl_Krmllib.h"
#include "Hacl_Krmllib.h"
#include "lib_intrinsics.h"

static uint32_t
Hacl_Bignum_Base_mul_wide_add2_u32(uint32_t a, uint32_t b, uint32_t c_in, uint32_t *out)
{
  uint32_t out0 = out[0U];
  uint64_t res = (uint64_t)a * (uint64_t)b + (uint64_t)c_in + (uint64_t)out0;
  out[0U] = (uint32_t)res;
  return (uint32_t)(res >> 32U);
}

static uint64_t
Hacl_Bignum_Base_mul_wide_add2_u64(uint64_t a, uint64_t b, uint64_t c_in, uint64_t *out)
{
  uint64_t out0 = out[0U];
  FStar_UInt128_uint128
  res =
    FStar_UInt128_add(FStar_UInt128_add(FStar_UInt128_mul_wide(a, b),
      FStar_UInt128_uint64_to_uint128(out0)),
        FStar_UInt128_uint64_to_uint128(c_in));
  out[0U] = FStar_UInt128_uint128_to_uint64(res);
  return FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(res, 64U));
}

static void
Hacl_Bignum_Convert_bn_from_bytes_be_uint64(uint32_t len, uint8_t *b, uint64_t *res)
{
  uint32_t bnLen = (len - 1U) / 8U + 1U;
  uint32_t tmpLen = 8U * bnLen;
  KRML_CHECK_SIZE(sizeof (uint8_t), tmpLen);
  uint8_t tmp[tmpLen];
  memset(tmp, 0U, tmpLen * sizeof (uint8_t));
  memcpy(tmp + tmpLen - len, b, len * sizeof (uint8_t));
  for (uint32_t i = 0U; i < bnLen; i++)
  {
    uint64_t *os = res;
    uint64_t u = load64_be(tmp + (bnLen - i - 1U) * 8U);
    uint64_t x = u;
    os[i] = x;
  }
}

static void
Hacl_Bignum_Convert_bn_to_bytes_be_uint64(uint32_t len, uint64_t *b, uint8_t *res)
{
  uint32_t bnLen = (len - 1U) / 8U + 1U;
  uint32_t tmpLen = 8U * bnLen;
  KRML_CHECK_SIZE(sizeof (uint8_t), tmpLen);
  uint8_t tmp[tmpLen];
  memset(tmp, 0U, tmpLen * sizeof (uint8_t));
  for (uint32_t i = 0U; i < bnLen; i++)
  {
    store64_be(tmp + i * 8U, b[bnLen - i - 1U]);
  }
  memcpy(res, tmp + tmpLen - len, len * sizeof (uint8_t));
}

static uint32_t Hacl_Bignum_Lib_bn_get_top_index_u32(uint32_t len, uint32_t *b)
{
  uint32_t priv = 0U;
  for (uint32_t i = 0U; i < len; i++)
  {
    uint32_t mask = FStar_UInt32_eq_mask(b[i], 0U);
    priv = (mask & priv) | (~mask & i);
  }
  return priv;
}

static uint64_t Hacl_Bignum_Lib_bn_get_top_index_u64(uint32_t len, uint64_t *b)
{
  uint64_t priv = 0ULL;
  for (uint32_t i = 0U; i < len; i++)
  {
    uint64_t mask = FStar_UInt64_eq_mask(b[i], 0ULL);
    priv = (mask & priv) | (~mask & (uint64_t)i);
  }
  return priv;
}

static uint32_t
Hacl_Bignum_Lib_bn_get_bits_u32(uint32_t len, uint32_t *b, uint32_t i, uint32_t l)
{
  uint32_t i1 = i / 32U;
  uint32_t j = i % 32U;
  uint32_t p1 = b[i1] >> j;
  uint32_t ite;
  if (i1 + 1U < len && 0U < j)
  {
    ite = p1 | b[i1 + 1U] << (32U - j);
  }
  else
  {
    ite = p1;
  }
  return ite & ((1U << l) - 1U);
}

static uint64_t
Hacl_Bignum_Lib_bn_get_bits_u64(uint32_t len, uint64_t *b, uint32_t i, uint32_t l)
{
  uint32_t i1 = i / 64U;
  uint32_t j = i % 64U;
  uint64_t p1 = b[i1] >> j;
  uint64_t ite;
  if (i1 + 1U < len && 0U < j)
  {
    ite = p1 | b[i1 + 1U] << (64U - j);
  }
  else
  {
    ite = p1;
  }
  return ite & ((1ULL << l) - 1ULL);
}

static uint32_t
Hacl_Bignum_Addition_bn_sub_eq_len_u32(uint32_t aLen, uint32_t *a, uint32_t *b, uint32_t *res)
{
  uint32_t c = 0U;
  for (uint32_t i = 0U; i < aLen / 4U; i++)
  {
    uint32_t t1 = a[4U * i];
    uint32_t t20 = b[4U * i];
    uint32_t *res_i0 = res + 4U * i;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u32(c, t1, t20, res_i0);
    uint32_t t10 = a[4U * i + 1U];
    uint32_t t21 = b[4U * i + 1U];
    uint32_t *res_i1 = res + 4U * i + 1U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u32(c, t10, t21, res_i1);
    uint32_t t11 = a[4U * i + 2U];
    uint32_t t22 = b[4U * i + 2U];
    uint32_t *res_i2 = res + 4U * i + 2U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u32(c, t11, t22, res_i2);
    uint32_t t12 = a[4U * i + 3U];
    uint32_t t2 = b[4U * i + 3U];
    uint32_t *res_i = res + 4U * i + 3U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u32(c, t12, t2, res_i);
  }
  for (uint32_t i = aLen / 4U * 4U; i < aLen; i++)
  {
    uint32_t t1 = a[i];
    uint32_t t2 = b[i];
    uint32_t *res_i = res + i;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u32(c, t1, t2, res_i);
  }
  return c;
}

static uint64_t
Hacl_Bignum_Addition_bn_sub_eq_len_u64(uint32_t aLen, uint64_t *a, uint64_t *b, uint64_t *res)
{
  uint64_t c = 0ULL;
  for (uint32_t i = 0U; i < aLen / 4U; i++)
  {
    uint64_t t1 = a[4U * i];
    uint64_t t20 = b[4U * i];
    uint64_t *res_i0 = res + 4U * i;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t1, t20, res_i0);
    uint64_t t10 = a[4U * i + 1U];
    uint64_t t21 = b[4U * i + 1U];
    uint64_t *res_i1 = res + 4U * i + 1U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t10, t21, res_i1);
    uint64_t t11 = a[4U * i + 2U];
    uint64_t t22 = b[4U * i + 2U];
    uint64_t *res_i2 = res + 4U * i + 2U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t11, t22, res_i2);
    uint64_t t12 = a[4U * i + 3U];
    uint64_t t2 = b[4U * i + 3U];
    uint64_t *res_i = res + 4U * i + 3U;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t12, t2, res_i);
  }
  for (uint32_t i = aLen / 4U * 4U; i < aLen; i++)
  {
    uint64_t t1 = a[i];
    uint64_t t2 = b[i];
    uint64_t *res_i = res + i;
    c = Lib_IntTypes_Intrinsics_sub_borrow_u64(c, t1, t2, res_i);
  }
  return c;
}

static uint32_t
Hacl_Bignum_Addition_bn_add_eq_len_u32(uint32_t aLen, uint32_t *a, uint32_t *b, uint32_t *res)
{
  uint32_t c = 0U;
  for (uint32_t i = 0U; i < aLen / 4U; i++)
  {
    uint32_t t1 = a[4U * i];
    uint32_t t20 = b[4U * i];
    uint32_t *res_i0 = res + 4U * i;
    c = Lib_IntTypes_Intrinsics_add_carry_u32(c, t1, t20, res_i0);
    uint32_t t10 = a[4U * i + 1U];
    uint32_t t21 = b[4U * i + 1U];
    uint32_t *res_i1 = res + 4U * i + 1U;
    c = Lib_IntTypes_Intrinsics_add_carry_u32(c, t10, t21, res_i1);
    uint32_t t11 = a[4U * i + 2U];
    uint32_t t22 = b[4U * i + 2U];
    uint32_t *res_i2 = res + 4U * i + 2U;
    c = Lib_IntTypes_Intrinsics_add_carry_u32(c, t11, t22, res_i2);
    uint32_t t12 = a[4U * i + 3U];
    uint32_t t2 = b[4U * i + 3U];
    uint32_t *res_i = res + 4U * i + 3U;
    c = Lib_IntTypes_Intrinsics_add_carry_u32(c, t12, t2, res_i);
  }
  for (uint32_t i = aLen / 4U * 4U; i < aLen; i++)
  {
    uint32_t t1 = a[i];
    uint32_t t2 = b[i];
    uint32_t *res_i = res + i;
    c = Lib_IntTypes_Intrinsics_add_carry_u32(c, t1, t2, res_i);
  }
  return c;
}

static uint64_t
Hacl_Bignum_Addition_bn_add_eq_len_u64(uint32_t aLen, uint64_t *a, uint64_t *b, uint64_t *res)
{
  uint64_t c = 0ULL;
  for (uint32_t i = 0U; i < aLen / 4U; i++)
  {
    uint64_t t1 = a[4U * i];
    uint64_t t20 = b[4U * i];
    uint64_t *res_i0 = res + 4U * i;
    c = Lib_IntTypes_Intrinsics_add_carry_u64(c, t1, t20, res_i0);
    uint64_t t10 = a[4U * i + 1U];
    uint64_t t21 = b[4U * i + 1U];
    uint64_t *res_i1 = res + 4U * i + 1U;
    c = Lib_IntTypes_Intrinsics_add_carry_u64(c, t10, t21, res_i1);
    uint64_t t11 = a[4U * i + 2U];
    uint64_t t22 = b[4U * i + 2U];
    uint64_t *res_i2 = res + 4U * i + 2U;
    c = Lib_IntTypes_Intrinsics_add_carry_u64(c, t11, t22, res_i2);
    uint64_t t12 = a[4U * i + 3U];
    uint64_t t2 = b[4U * i + 3U];
    uint64_t *res_i = res + 4U * i + 3U;
    c = Lib_IntTypes_Intrinsics_add_carry_u64(c, t12, t2, res_i);
  }
  for (uint32_t i = aLen / 4U * 4U; i < aLen; i++)
  {
    uint64_t t1 = a[i];
    uint64_t t2 = b[i];
    uint64_t *res_i = res + i;
    c = Lib_IntTypes_Intrinsics_add_carry_u64(c, t1, t2, res_i);
  }
  return c;
}

static void
Hacl_Bignum_Multiplication_bn_mul_u32(
  uint32_t aLen,
  uint32_t *a,
  uint32_t bLen,
  uint32_t *b,
  uint32_t *res
)
{
  memset(res, 0U, (aLen + bLen) * sizeof (uint32_t));
  for (uint32_t i0 = 0U; i0 < bLen; i0++)
  {
    uint32_t bj = b[i0];
    uint32_t *res_j = res + i0;
    uint32_t c = 0U;
    for (uint32_t i = 0U; i < aLen / 8U; i++)
    {
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+0], bj, c, res_j + 8*i + 0);
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+1], bj, c, res_j + 8*i + 1);
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+2], bj, c, res_j + 8*i + 2);
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+3], bj, c, res_j + 8*i + 3);
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+4], bj, c, res_j + 8*i + 4);
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+5], bj, c, res_j + 8*i + 5);
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+6], bj, c, res_j + 8*i + 6);
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a[8*i+7], bj, c, res_j + 8*i + 7);
    }
    for (uint32_t i = aLen / 8U * 8U; i < aLen; i++)
    {
      uint32_t a_i = a[i];
      uint32_t *res_i = res_j + i;
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a_i, bj, c, res_i);
    }
    uint32_t r = c;
    res[aLen + i0] = r;
  }
}

static void
Hacl_Bignum_Multiplication_bn_mul_u64(
  uint32_t aLen,
  uint64_t *a,
  uint32_t bLen,
  uint64_t *b,
  uint64_t *res
)
{
  memset(res, 0U, (aLen + bLen) * sizeof (uint64_t));
  for (uint32_t i0 = 0U; i0 < bLen; i0++)
  {
    uint64_t bj = b[i0];
    uint64_t *res_j = res + i0;
    uint64_t c = 0ULL;
    for (uint32_t i = 0U; i < aLen / 8U; i++)
    {
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+0], bj, c, res_j + 8*i + 0);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+1], bj, c, res_j + 8*i + 1);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+2], bj, c, res_j + 8*i + 2);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+3], bj, c, res_j + 8*i + 3);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+4], bj, c, res_j + 8*i + 4);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+5], bj, c, res_j + 8*i + 5);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+6], bj, c, res_j + 8*i + 6);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a[8*i+7], bj, c, res_j + 8*i + 7);
    }
    for (uint32_t i = aLen / 8U * 8U; i < aLen; i++)
    {
      uint64_t a_i = a[i];
      uint64_t *res_i = res_j + i;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, bj, c, res_i);
    }
    uint64_t r = c;
    res[aLen + i0] = r;
  }
}

static void
Hacl_Bignum_Multiplication_bn_sqr_u32(uint32_t aLen, uint32_t *a, uint32_t *res)
{
  memset(res, 0U, (aLen + aLen) * sizeof (uint32_t));
  for (uint32_t i0 = 0U; i0 < aLen; i0++)
  {
    uint32_t *ab = a;
    uint32_t a_j = a[i0];
    uint32_t *res_j = res + i0;
    uint32_t c = 0U;
    for (uint32_t i = 0U; i < i0 / 4U; i++)
    {
      uint32_t a_i = ab[4U * i];
      uint32_t *res_i0 = res_j + 4U * i;
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a_i, a_j, c, res_i0);
      uint32_t a_i0 = ab[4U * i + 1U];
      uint32_t *res_i1 = res_j + 4U * i + 1U;
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a_i0, a_j, c, res_i1);
      uint32_t a_i1 = ab[4U * i + 2U];
      uint32_t *res_i2 = res_j + 4U * i + 2U;
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a_i1, a_j, c, res_i2);
      uint32_t a_i2 = ab[4U * i + 3U];
      uint32_t *res_i = res_j + 4U * i + 3U;
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a_i2, a_j, c, res_i);
    }
    for (uint32_t i = i0 / 4U * 4U; i < i0; i++)
    {
      uint32_t a_i = ab[i];
      uint32_t *res_i = res_j + i;
      c = Hacl_Bignum_Base_mul_wide_add2_u32(a_i, a_j, c, res_i);
    }
    uint32_t r = c;
    res[i0 + i0] = r;
  }
  uint32_t c0 = Hacl_Bignum_Addition_bn_add_eq_len_u32(aLen + aLen, res, res, res);
  KRML_MAYBE_UNUSED_VAR(c0);
  KRML_CHECK_SIZE(sizeof (uint32_t), aLen + aLen);
  uint32_t tmp[aLen + aLen];
  memset(tmp, 0U, (aLen + aLen) * sizeof (uint32_t));
  for (uint32_t i = 0U; i < aLen; i++)
  {
    uint64_t res1 = (uint64_t)a[i] * (uint64_t)a[i];
    uint32_t hi = (uint32_t)(res1 >> 32U);
    uint32_t lo = (uint32_t)res1;
    tmp[2U * i] = lo;
    tmp[2U * i + 1U] = hi;
  }
  uint32_t c1 = Hacl_Bignum_Addition_bn_add_eq_len_u32(aLen + aLen, res, tmp, res);
  KRML_MAYBE_UNUSED_VAR(c1);
}

static void
Hacl_Bignum_Multiplication_bn_sqr_u64(uint32_t aLen, uint64_t *a, uint64_t *res)
{
  memset(res, 0U, (aLen + aLen) * sizeof (uint64_t));
  for (uint32_t i0 = 0U; i0 < aLen; i0++)
  {
    uint64_t *ab = a;
    uint64_t a_j = a[i0];
    uint64_t *res_j = res + i0;
    uint64_t c = 0ULL;
    for (uint32_t i = 0U; i < i0 / 8U; i++)
    {
/*
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+0], a_j, c, res_j+8*i+0);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+1], a_j, c, res_j+8*i+1);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+2], a_j, c, res_j+8*i+2);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+3], a_j, c, res_j+8*i+3);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+4], a_j, c, res_j+8*i+4);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+5], a_j, c, res_j+8*i+5);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+6], a_j, c, res_j+8*i+6);
      c = Hacl_Bignum_Base_mul_wide_add2_u64(ab[8*i+7], a_j, c, res_j+8*i+7);
*/
      uint64_t *n = ab;
      uint64_t *res_j0 = res_j;
      uint64_t qj = a_j; 
      uint64_t c1 = c;
      FStar_UInt128_uint128 ab0 = FStar_UInt128_mul_wide(n[8*i], qj);
      FStar_UInt128_uint128 abo0 = FStar_UInt128_add(ab0, FStar_UInt128_uint64_to_uint128(res_j0[8*i]));
      FStar_UInt128_uint128 ab1 = FStar_UInt128_mul_wide(n[8*i+1], qj);
      FStar_UInt128_uint128 abo1 = FStar_UInt128_add(ab1, FStar_UInt128_uint64_to_uint128(res_j0[8*i+1]));
      FStar_UInt128_uint128 ab2 = FStar_UInt128_mul_wide(n[8*i+2], qj);
      FStar_UInt128_uint128 abo2 = FStar_UInt128_add(ab2, FStar_UInt128_uint64_to_uint128(res_j0[8*i+2]));
      FStar_UInt128_uint128 ab3 = FStar_UInt128_mul_wide(n[8*i+3], qj);
      FStar_UInt128_uint128 abo3 = FStar_UInt128_add(ab3, FStar_UInt128_uint64_to_uint128(res_j0[8*i+3]));

      FStar_UInt128_uint128 abco0 = FStar_UInt128_add(abo0, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco0, 64U));

      FStar_UInt128_uint128 ab4 = FStar_UInt128_mul_wide(n[8*i+4], qj);
      FStar_UInt128_uint128 abo4 = FStar_UInt128_add(ab4, FStar_UInt128_uint64_to_uint128(res_j0[8*i+4]));

      FStar_UInt128_uint128 abco1 = FStar_UInt128_add(abo1, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco1, 64U));

      FStar_UInt128_uint128 ab5 = FStar_UInt128_mul_wide(n[8*i+5], qj);
      FStar_UInt128_uint128 abo5 = FStar_UInt128_add(ab5, FStar_UInt128_uint64_to_uint128(res_j0[8*i+5]));

      FStar_UInt128_uint128 abco2 = FStar_UInt128_add(abo2, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco2, 64U));

      FStar_UInt128_uint128 ab6 = FStar_UInt128_mul_wide(n[8*i+6], qj);
      FStar_UInt128_uint128 abo6 = FStar_UInt128_add(ab6, FStar_UInt128_uint64_to_uint128(res_j0[8*i+6]));

      FStar_UInt128_uint128 abco3 = FStar_UInt128_add(abo3, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco3, 64U));

      FStar_UInt128_uint128 ab7 = FStar_UInt128_mul_wide(n[8*i+7], qj);
      FStar_UInt128_uint128 abo7 = FStar_UInt128_add(ab7, FStar_UInt128_uint64_to_uint128(res_j0[8*i+7]));

      FStar_UInt128_uint128 abco4 = FStar_UInt128_add(abo4, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco4, 64U));
      FStar_UInt128_uint128 abco5 = FStar_UInt128_add(abo5, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco5, 64U));
      FStar_UInt128_uint128 abco6 = FStar_UInt128_add(abo6, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco6, 64U));
      FStar_UInt128_uint128 abco7 = FStar_UInt128_add(abo7, FStar_UInt128_uint64_to_uint128(c1));
      c1 = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(abco7, 64U));

      res_j0[8*i] = FStar_UInt128_uint128_to_uint64(abco0);
      res_j0[8*i+1] = FStar_UInt128_uint128_to_uint64(abco1);
      res_j0[8*i+2] = FStar_UInt128_uint128_to_uint64(abco2);
      res_j0[8*i+3] = FStar_UInt128_uint128_to_uint64(abco3);

      res_j0[8*i+4] = FStar_UInt128_uint128_to_uint64(abco4);
      res_j0[8*i+5] = FStar_UInt128_uint128_to_uint64(abco5);
      res_j0[8*i+6] = FStar_UInt128_uint128_to_uint64(abco6);
      res_j0[8*i+7] = FStar_UInt128_uint128_to_uint64(abco7);

      c = c1;
    }
    for (uint32_t i = i0 / 8U * 8U; i < i0; i++)
    {
      uint64_t a_i = ab[i];
      uint64_t *res_i = res_j + i;
      c = Hacl_Bignum_Base_mul_wide_add2_u64(a_i, a_j, c, res_i);
    }
    uint64_t r = c;
    res[i0 + i0] = r;
  }
  uint64_t c0 = Hacl_Bignum_Addition_bn_add_eq_len_u64(aLen + aLen, res, res, res);
  KRML_MAYBE_UNUSED_VAR(c0);
  KRML_CHECK_SIZE(sizeof (uint64_t), aLen + aLen);
  uint64_t tmp[aLen + aLen];
  memset(tmp, 0U, (aLen + aLen) * sizeof (uint64_t));
  for (uint32_t i = 0U; i < aLen; i++)
  {
    FStar_UInt128_uint128 res1 = FStar_UInt128_mul_wide(a[i], a[i]);
    uint64_t hi = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(res1, 64U));
    uint64_t lo = FStar_UInt128_uint128_to_uint64(res1);
    tmp[2U * i] = lo;
    tmp[2U * i + 1U] = hi;
  }
  uint64_t c1 = Hacl_Bignum_Addition_bn_add_eq_len_u64(aLen + aLen, res, tmp, res);
  KRML_MAYBE_UNUSED_VAR(c1);
}

#if defined(__cplusplus)
}
#endif

#define __internal_Hacl_Bignum_Base_H_DEFINED
#endif
