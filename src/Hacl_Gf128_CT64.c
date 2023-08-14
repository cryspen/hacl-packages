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


#include "Hacl_Gf128_CT64.h"

static inline void fmul0(uint64_t *x, uint64_t *y)
{
  uint64_t uu____0 = y[0U];
  uint64_t
  x10 =
    (uu____0 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____0 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x20 =
    (x10 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x10 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x30 =
    (x20 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x20 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x4 =
    (x30 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x30 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x5 =
    (x4 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x4 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t yr1 = x5 << (uint32_t)32U | x5 >> (uint32_t)32U;
  uint64_t uu____1 = y[1U];
  uint64_t
  x11 =
    (uu____1 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____1 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x21 =
    (x11 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x11 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x31 =
    (x21 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x21 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x40 =
    (x31 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x31 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x50 =
    (x40 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x40 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t yr2 = x50 << (uint32_t)32U | x50 >> (uint32_t)32U;
  uint64_t uu____2 = x[0U];
  uint64_t uu____3 = x[1U];
  uint64_t uu____4 = y[0U];
  uint64_t uu____5 = y[1U];
  uint64_t uu____6 = y[0U] ^ y[1U];
  uint64_t
  x12 =
    (uu____2 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____2 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x22 =
    (x12 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x12 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x32 =
    (x22 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x22 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x41 =
    (x32 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x32 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x51 =
    (x41 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x41 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y1r = x51 << (uint32_t)32U | x51 >> (uint32_t)32U;
  uint64_t
  x13 =
    (uu____3 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____3 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x23 =
    (x13 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x13 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x33 =
    (x23 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x23 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x42 =
    (x33 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x33 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x52 =
    (x42 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x42 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y2r = x52 << (uint32_t)32U | x52 >> (uint32_t)32U;
  uint64_t y3 = uu____2 ^ uu____3;
  uint64_t y3r = y1r ^ y2r;
  uint64_t x00 = uu____2 & (uint64_t)0x1111111111111111U;
  uint64_t x14 = uu____2 & (uint64_t)0x2222222222222222U;
  uint64_t x24 = uu____2 & (uint64_t)0x4444444444444444U;
  uint64_t x34 = uu____2 & (uint64_t)0x8888888888888888U;
  uint64_t y00 = uu____4 & (uint64_t)0x1111111111111111U;
  uint64_t y10 = uu____4 & (uint64_t)0x2222222222222222U;
  uint64_t y20 = uu____4 & (uint64_t)0x4444444444444444U;
  uint64_t y310 = uu____4 & (uint64_t)0x8888888888888888U;
  uint64_t z0 = x00 * y00 ^ (x14 * y310 ^ (x24 * y20 ^ x34 * y10));
  uint64_t z10 = x00 * y10 ^ (x14 * y00 ^ (x24 * y310 ^ x34 * y20));
  uint64_t z20 = x00 * y20 ^ (x14 * y10 ^ (x24 * y00 ^ x34 * y310));
  uint64_t z30 = x00 * y310 ^ (x14 * y20 ^ (x24 * y10 ^ x34 * y00));
  uint64_t
  z00 =
    (((z0 & (uint64_t)0x1111111111111111U) | (z10 & (uint64_t)0x2222222222222222U))
    | (z20 & (uint64_t)0x4444444444444444U))
    | (z30 & (uint64_t)0x8888888888888888U);
  uint64_t x01 = uu____3 & (uint64_t)0x1111111111111111U;
  uint64_t x15 = uu____3 & (uint64_t)0x2222222222222222U;
  uint64_t x25 = uu____3 & (uint64_t)0x4444444444444444U;
  uint64_t x35 = uu____3 & (uint64_t)0x8888888888888888U;
  uint64_t y01 = uu____5 & (uint64_t)0x1111111111111111U;
  uint64_t y11 = uu____5 & (uint64_t)0x2222222222222222U;
  uint64_t y21 = uu____5 & (uint64_t)0x4444444444444444U;
  uint64_t y311 = uu____5 & (uint64_t)0x8888888888888888U;
  uint64_t z010 = x01 * y01 ^ (x15 * y311 ^ (x25 * y21 ^ x35 * y11));
  uint64_t z12 = x01 * y11 ^ (x15 * y01 ^ (x25 * y311 ^ x35 * y21));
  uint64_t z22 = x01 * y21 ^ (x15 * y11 ^ (x25 * y01 ^ x35 * y311));
  uint64_t z31 = x01 * y311 ^ (x15 * y21 ^ (x25 * y11 ^ x35 * y01));
  uint64_t
  z13 =
    (((z010 & (uint64_t)0x1111111111111111U) | (z12 & (uint64_t)0x2222222222222222U))
    | (z22 & (uint64_t)0x4444444444444444U))
    | (z31 & (uint64_t)0x8888888888888888U);
  uint64_t x02 = y3 & (uint64_t)0x1111111111111111U;
  uint64_t x16 = y3 & (uint64_t)0x2222222222222222U;
  uint64_t x26 = y3 & (uint64_t)0x4444444444444444U;
  uint64_t x36 = y3 & (uint64_t)0x8888888888888888U;
  uint64_t y02 = uu____6 & (uint64_t)0x1111111111111111U;
  uint64_t y12 = uu____6 & (uint64_t)0x2222222222222222U;
  uint64_t y22 = uu____6 & (uint64_t)0x4444444444444444U;
  uint64_t y312 = uu____6 & (uint64_t)0x8888888888888888U;
  uint64_t z011 = x02 * y02 ^ (x16 * y312 ^ (x26 * y22 ^ x36 * y12));
  uint64_t z110 = x02 * y12 ^ (x16 * y02 ^ (x26 * y312 ^ x36 * y22));
  uint64_t z23 = x02 * y22 ^ (x16 * y12 ^ (x26 * y02 ^ x36 * y312));
  uint64_t z32 = x02 * y312 ^ (x16 * y22 ^ (x26 * y12 ^ x36 * y02));
  uint64_t
  z24 =
    (((z011 & (uint64_t)0x1111111111111111U) | (z110 & (uint64_t)0x2222222222222222U))
    | (z23 & (uint64_t)0x4444444444444444U))
    | (z32 & (uint64_t)0x8888888888888888U);
  uint64_t x03 = y1r & (uint64_t)0x1111111111111111U;
  uint64_t x17 = y1r & (uint64_t)0x2222222222222222U;
  uint64_t x27 = y1r & (uint64_t)0x4444444444444444U;
  uint64_t x37 = y1r & (uint64_t)0x8888888888888888U;
  uint64_t y03 = yr1 & (uint64_t)0x1111111111111111U;
  uint64_t y13 = yr1 & (uint64_t)0x2222222222222222U;
  uint64_t y23 = yr1 & (uint64_t)0x4444444444444444U;
  uint64_t y313 = yr1 & (uint64_t)0x8888888888888888U;
  uint64_t z012 = x03 * y03 ^ (x17 * y313 ^ (x27 * y23 ^ x37 * y13));
  uint64_t z111 = x03 * y13 ^ (x17 * y03 ^ (x27 * y313 ^ x37 * y23));
  uint64_t z210 = x03 * y23 ^ (x17 * y13 ^ (x27 * y03 ^ x37 * y313));
  uint64_t z33 = x03 * y313 ^ (x17 * y23 ^ (x27 * y13 ^ x37 * y03));
  uint64_t
  z0h =
    (((z012 & (uint64_t)0x1111111111111111U) | (z111 & (uint64_t)0x2222222222222222U))
    | (z210 & (uint64_t)0x4444444444444444U))
    | (z33 & (uint64_t)0x8888888888888888U);
  uint64_t x04 = y2r & (uint64_t)0x1111111111111111U;
  uint64_t x18 = y2r & (uint64_t)0x2222222222222222U;
  uint64_t x28 = y2r & (uint64_t)0x4444444444444444U;
  uint64_t x38 = y2r & (uint64_t)0x8888888888888888U;
  uint64_t y04 = yr2 & (uint64_t)0x1111111111111111U;
  uint64_t y14 = yr2 & (uint64_t)0x2222222222222222U;
  uint64_t y24 = yr2 & (uint64_t)0x4444444444444444U;
  uint64_t y314 = yr2 & (uint64_t)0x8888888888888888U;
  uint64_t z013 = x04 * y04 ^ (x18 * y314 ^ (x28 * y24 ^ x38 * y14));
  uint64_t z112 = x04 * y14 ^ (x18 * y04 ^ (x28 * y314 ^ x38 * y24));
  uint64_t z211 = x04 * y24 ^ (x18 * y14 ^ (x28 * y04 ^ x38 * y314));
  uint64_t z34 = x04 * y314 ^ (x18 * y24 ^ (x28 * y14 ^ x38 * y04));
  uint64_t
  z1h =
    (((z013 & (uint64_t)0x1111111111111111U) | (z112 & (uint64_t)0x2222222222222222U))
    | (z211 & (uint64_t)0x4444444444444444U))
    | (z34 & (uint64_t)0x8888888888888888U);
  uint64_t x0 = y3r & (uint64_t)0x1111111111111111U;
  uint64_t x19 = y3r & (uint64_t)0x2222222222222222U;
  uint64_t x29 = y3r & (uint64_t)0x4444444444444444U;
  uint64_t x3 = y3r & (uint64_t)0x8888888888888888U;
  uint64_t y0 = (yr1 ^ yr2) & (uint64_t)0x1111111111111111U;
  uint64_t y1 = (yr1 ^ yr2) & (uint64_t)0x2222222222222222U;
  uint64_t y2 = (yr1 ^ yr2) & (uint64_t)0x4444444444444444U;
  uint64_t y31 = (yr1 ^ yr2) & (uint64_t)0x8888888888888888U;
  uint64_t z01 = x0 * y0 ^ (x19 * y31 ^ (x29 * y2 ^ x3 * y1));
  uint64_t z11 = x0 * y1 ^ (x19 * y0 ^ (x29 * y31 ^ x3 * y2));
  uint64_t z212 = x0 * y2 ^ (x19 * y1 ^ (x29 * y0 ^ x3 * y31));
  uint64_t z35 = x0 * y31 ^ (x19 * y2 ^ (x29 * y1 ^ x3 * y0));
  uint64_t
  z2h =
    (((z01 & (uint64_t)0x1111111111111111U) | (z11 & (uint64_t)0x2222222222222222U))
    | (z212 & (uint64_t)0x4444444444444444U))
    | (z35 & (uint64_t)0x8888888888888888U);
  uint64_t z21 = z24 ^ (z00 ^ z13);
  uint64_t z2h1 = z2h ^ (z0h ^ z1h);
  uint64_t
  x110 =
    (z0h & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z0h >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x210 =
    (x110 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x110 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x39 =
    (x210 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x210 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x43 =
    (x39 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x39 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x53 =
    (x43 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x43 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z0h1 = (x53 << (uint32_t)32U | x53 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x111 =
    (z1h & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z1h >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x211 =
    (x111 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x111 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x310 =
    (x211 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x211 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x44 =
    (x310 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x310 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x54 =
    (x44 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x44 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z1h1 = (x54 << (uint32_t)32U | x54 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x1 =
    (z2h1 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z2h1 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x212 =
    (x1 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x1 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x311 =
    (x212 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x212 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x45 =
    (x311 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x311 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x55 =
    (x45 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x45 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z2h2 = (x55 << (uint32_t)32U | x55 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t z1 = z00;
  uint64_t z2 = z0h1 ^ z21;
  uint64_t z3 = z13 ^ z2h2;
  uint64_t z4 = z1h1;
  uint64_t v3 = z4 << (uint32_t)1U | z3 >> (uint32_t)63U;
  uint64_t v2 = z3 << (uint32_t)1U | z2 >> (uint32_t)63U;
  uint64_t v1 = z2 << (uint32_t)1U | z1 >> (uint32_t)63U;
  uint64_t v0 = z1 << (uint32_t)1U;
  uint64_t v21 = v2 ^ (v0 ^ (v0 >> (uint32_t)1U ^ (v0 >> (uint32_t)2U ^ v0 >> (uint32_t)7U)));
  uint64_t v11 = v1 ^ (v0 << (uint32_t)63U ^ (v0 << (uint32_t)62U ^ v0 << (uint32_t)57U));
  uint64_t
  v31 = v3 ^ (v11 ^ (v11 >> (uint32_t)1U ^ (v11 >> (uint32_t)2U ^ v11 >> (uint32_t)7U)));
  uint64_t v22 = v21 ^ (v11 << (uint32_t)63U ^ (v11 << (uint32_t)62U ^ v11 << (uint32_t)57U));
  uint64_t x112 = v22;
  uint64_t x2 = v31;
  x[0U] = x112;
  x[1U] = x2;
}

static inline void load_precompute_r(uint64_t *pre, uint8_t *key)
{
  uint64_t *h1_0 = pre + (uint32_t)6U;
  uint64_t *h2_0 = pre + (uint32_t)4U;
  uint64_t *h3_0 = pre + (uint32_t)2U;
  uint64_t *h4_0 = pre;
  uint64_t u = load64_be(key);
  h1_0[1U] = u;
  uint64_t u0 = load64_be(key + (uint32_t)8U);
  h1_0[0U] = u0;
  h2_0[0U] = h1_0[0U];
  h2_0[1U] = h1_0[1U];
  h3_0[0U] = h1_0[0U];
  h3_0[1U] = h1_0[1U];
  h4_0[0U] = h1_0[0U];
  h4_0[1U] = h1_0[1U];
  fmul0(h2_0, h1_0);
  fmul0(h3_0, h2_0);
  fmul0(h4_0, h3_0);
  uint64_t uu____0 = h1_0[0U];
  uint64_t
  x =
    (uu____0 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____0 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x1 =
    (x & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x2 =
    (x1 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x1 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x3 =
    (x2 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x2 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x4 =
    (x3 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x3 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[14U] = x4 << (uint32_t)32U | x4 >> (uint32_t)32U;
  uint64_t uu____1 = h1_0[1U];
  uint64_t
  x0 =
    (uu____1 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____1 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x10 =
    (x0 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x0 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x20 =
    (x10 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x10 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x30 =
    (x20 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x20 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x40 =
    (x30 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x30 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[15U] = x40 << (uint32_t)32U | x40 >> (uint32_t)32U;
  uint64_t uu____2 = h2_0[0U];
  uint64_t
  x5 =
    (uu____2 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____2 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x11 =
    (x5 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x5 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x21 =
    (x11 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x11 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x31 =
    (x21 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x21 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x41 =
    (x31 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x31 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[12U] = x41 << (uint32_t)32U | x41 >> (uint32_t)32U;
  uint64_t uu____3 = h2_0[1U];
  uint64_t
  x6 =
    (uu____3 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____3 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x12 =
    (x6 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x6 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x22 =
    (x12 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x12 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x32 =
    (x22 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x22 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x42 =
    (x32 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x32 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[13U] = x42 << (uint32_t)32U | x42 >> (uint32_t)32U;
  uint64_t uu____4 = h3_0[0U];
  uint64_t
  x7 =
    (uu____4 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____4 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x13 =
    (x7 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x7 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x23 =
    (x13 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x13 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x33 =
    (x23 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x23 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x43 =
    (x33 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x33 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[10U] = x43 << (uint32_t)32U | x43 >> (uint32_t)32U;
  uint64_t uu____5 = h3_0[1U];
  uint64_t
  x8 =
    (uu____5 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____5 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x14 =
    (x8 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x8 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x24 =
    (x14 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x14 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x34 =
    (x24 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x24 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x44 =
    (x34 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x34 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[11U] = x44 << (uint32_t)32U | x44 >> (uint32_t)32U;
  uint64_t uu____6 = h4_0[0U];
  uint64_t
  x9 =
    (uu____6 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____6 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x15 =
    (x9 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x9 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x25 =
    (x15 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x15 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x35 =
    (x25 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x25 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x45 =
    (x35 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x35 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[8U] = x45 << (uint32_t)32U | x45 >> (uint32_t)32U;
  uint64_t uu____7 = h4_0[1U];
  uint64_t
  x16 =
    (uu____7 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____7 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x17 =
    (x16 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x16 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x26 =
    (x17 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x17 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x36 =
    (x26 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x26 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x46 =
    (x36 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x36 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  pre[9U] = x46 << (uint32_t)32U | x46 >> (uint32_t)32U;
}

static inline void normalize4(uint64_t *acc, uint64_t *x, uint64_t *pre)
{
  uint64_t *x1 = x;
  uint64_t *x2 = x + (uint32_t)2U;
  uint64_t *x3 = x + (uint32_t)4U;
  uint64_t *x4 = x + (uint32_t)6U;
  uint64_t *y1 = pre;
  uint64_t *y2 = pre + (uint32_t)2U;
  uint64_t *y3 = pre + (uint32_t)4U;
  uint64_t *y4 = pre + (uint32_t)6U;
  uint64_t *yr1 = pre + (uint32_t)8U;
  uint64_t *yr2 = pre + (uint32_t)10U;
  uint64_t *yr3 = pre + (uint32_t)12U;
  uint64_t *yr4 = pre + (uint32_t)14U;
  uint64_t uu____0 = x1[0U];
  uint64_t uu____1 = x1[1U];
  uint64_t uu____2 = y1[0U];
  uint64_t uu____3 = y1[1U];
  uint64_t uu____4 = y1[0U] ^ y1[1U];
  uint64_t uu____5 = yr1[0U];
  uint64_t uu____6 = yr1[1U];
  uint64_t uu____7 = yr1[0U] ^ yr1[1U];
  uint64_t
  x50 =
    (uu____0 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____0 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x6 =
    (x50 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x50 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x7 =
    (x6 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x6 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x8 =
    (x7 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x7 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x9 =
    (x8 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x8 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y1r = x9 << (uint32_t)32U | x9 >> (uint32_t)32U;
  uint64_t
  x51 =
    (uu____1 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____1 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x60 =
    (x51 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x51 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x70 =
    (x60 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x60 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x80 =
    (x70 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x70 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x90 =
    (x80 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x80 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y2r = x90 << (uint32_t)32U | x90 >> (uint32_t)32U;
  uint64_t y310 = uu____0 ^ uu____1;
  uint64_t y3r0 = y1r ^ y2r;
  uint64_t x00 = uu____0 & (uint64_t)0x1111111111111111U;
  uint64_t x110 = uu____0 & (uint64_t)0x2222222222222222U;
  uint64_t x210 = uu____0 & (uint64_t)0x4444444444444444U;
  uint64_t x310 = uu____0 & (uint64_t)0x8888888888888888U;
  uint64_t y00 = uu____2 & (uint64_t)0x1111111111111111U;
  uint64_t y110 = uu____2 & (uint64_t)0x2222222222222222U;
  uint64_t y210 = uu____2 & (uint64_t)0x4444444444444444U;
  uint64_t y320 = uu____2 & (uint64_t)0x8888888888888888U;
  uint64_t z00 = x00 * y00 ^ (x110 * y320 ^ (x210 * y210 ^ x310 * y110));
  uint64_t z10 = x00 * y110 ^ (x110 * y00 ^ (x210 * y320 ^ x310 * y210));
  uint64_t z20 = x00 * y210 ^ (x110 * y110 ^ (x210 * y00 ^ x310 * y320));
  uint64_t z30 = x00 * y320 ^ (x110 * y210 ^ (x210 * y110 ^ x310 * y00));
  uint64_t
  z02 =
    (((z00 & (uint64_t)0x1111111111111111U) | (z10 & (uint64_t)0x2222222222222222U))
    | (z20 & (uint64_t)0x4444444444444444U))
    | (z30 & (uint64_t)0x8888888888888888U);
  uint64_t x01 = uu____1 & (uint64_t)0x1111111111111111U;
  uint64_t x111 = uu____1 & (uint64_t)0x2222222222222222U;
  uint64_t x211 = uu____1 & (uint64_t)0x4444444444444444U;
  uint64_t x311 = uu____1 & (uint64_t)0x8888888888888888U;
  uint64_t y01 = uu____3 & (uint64_t)0x1111111111111111U;
  uint64_t y111 = uu____3 & (uint64_t)0x2222222222222222U;
  uint64_t y211 = uu____3 & (uint64_t)0x4444444444444444U;
  uint64_t y321 = uu____3 & (uint64_t)0x8888888888888888U;
  uint64_t z010 = x01 * y01 ^ (x111 * y321 ^ (x211 * y211 ^ x311 * y111));
  uint64_t z14 = x01 * y111 ^ (x111 * y01 ^ (x211 * y321 ^ x311 * y211));
  uint64_t z24 = x01 * y211 ^ (x111 * y111 ^ (x211 * y01 ^ x311 * y321));
  uint64_t z33 = x01 * y321 ^ (x111 * y211 ^ (x211 * y111 ^ x311 * y01));
  uint64_t
  z15 =
    (((z010 & (uint64_t)0x1111111111111111U) | (z14 & (uint64_t)0x2222222222222222U))
    | (z24 & (uint64_t)0x4444444444444444U))
    | (z33 & (uint64_t)0x8888888888888888U);
  uint64_t x02 = y310 & (uint64_t)0x1111111111111111U;
  uint64_t x112 = y310 & (uint64_t)0x2222222222222222U;
  uint64_t x212 = y310 & (uint64_t)0x4444444444444444U;
  uint64_t x312 = y310 & (uint64_t)0x8888888888888888U;
  uint64_t y02 = uu____4 & (uint64_t)0x1111111111111111U;
  uint64_t y112 = uu____4 & (uint64_t)0x2222222222222222U;
  uint64_t y212 = uu____4 & (uint64_t)0x4444444444444444U;
  uint64_t y322 = uu____4 & (uint64_t)0x8888888888888888U;
  uint64_t z011 = x02 * y02 ^ (x112 * y322 ^ (x212 * y212 ^ x312 * y112));
  uint64_t z110 = x02 * y112 ^ (x112 * y02 ^ (x212 * y322 ^ x312 * y212));
  uint64_t z25 = x02 * y212 ^ (x112 * y112 ^ (x212 * y02 ^ x312 * y322));
  uint64_t z34 = x02 * y322 ^ (x112 * y212 ^ (x212 * y112 ^ x312 * y02));
  uint64_t
  z26 =
    (((z011 & (uint64_t)0x1111111111111111U) | (z110 & (uint64_t)0x2222222222222222U))
    | (z25 & (uint64_t)0x4444444444444444U))
    | (z34 & (uint64_t)0x8888888888888888U);
  uint64_t x03 = y1r & (uint64_t)0x1111111111111111U;
  uint64_t x113 = y1r & (uint64_t)0x2222222222222222U;
  uint64_t x213 = y1r & (uint64_t)0x4444444444444444U;
  uint64_t x313 = y1r & (uint64_t)0x8888888888888888U;
  uint64_t y03 = uu____5 & (uint64_t)0x1111111111111111U;
  uint64_t y113 = uu____5 & (uint64_t)0x2222222222222222U;
  uint64_t y213 = uu____5 & (uint64_t)0x4444444444444444U;
  uint64_t y323 = uu____5 & (uint64_t)0x8888888888888888U;
  uint64_t z012 = x03 * y03 ^ (x113 * y323 ^ (x213 * y213 ^ x313 * y113));
  uint64_t z111 = x03 * y113 ^ (x113 * y03 ^ (x213 * y323 ^ x313 * y213));
  uint64_t z210 = x03 * y213 ^ (x113 * y113 ^ (x213 * y03 ^ x313 * y323));
  uint64_t z35 = x03 * y323 ^ (x113 * y213 ^ (x213 * y113 ^ x313 * y03));
  uint64_t
  z0h =
    (((z012 & (uint64_t)0x1111111111111111U) | (z111 & (uint64_t)0x2222222222222222U))
    | (z210 & (uint64_t)0x4444444444444444U))
    | (z35 & (uint64_t)0x8888888888888888U);
  uint64_t x04 = y2r & (uint64_t)0x1111111111111111U;
  uint64_t x114 = y2r & (uint64_t)0x2222222222222222U;
  uint64_t x214 = y2r & (uint64_t)0x4444444444444444U;
  uint64_t x314 = y2r & (uint64_t)0x8888888888888888U;
  uint64_t y04 = uu____6 & (uint64_t)0x1111111111111111U;
  uint64_t y114 = uu____6 & (uint64_t)0x2222222222222222U;
  uint64_t y214 = uu____6 & (uint64_t)0x4444444444444444U;
  uint64_t y324 = uu____6 & (uint64_t)0x8888888888888888U;
  uint64_t z013 = x04 * y04 ^ (x114 * y324 ^ (x214 * y214 ^ x314 * y114));
  uint64_t z112 = x04 * y114 ^ (x114 * y04 ^ (x214 * y324 ^ x314 * y214));
  uint64_t z211 = x04 * y214 ^ (x114 * y114 ^ (x214 * y04 ^ x314 * y324));
  uint64_t z36 = x04 * y324 ^ (x114 * y214 ^ (x214 * y114 ^ x314 * y04));
  uint64_t
  z1h =
    (((z013 & (uint64_t)0x1111111111111111U) | (z112 & (uint64_t)0x2222222222222222U))
    | (z211 & (uint64_t)0x4444444444444444U))
    | (z36 & (uint64_t)0x8888888888888888U);
  uint64_t x05 = y3r0 & (uint64_t)0x1111111111111111U;
  uint64_t x115 = y3r0 & (uint64_t)0x2222222222222222U;
  uint64_t x215 = y3r0 & (uint64_t)0x4444444444444444U;
  uint64_t x315 = y3r0 & (uint64_t)0x8888888888888888U;
  uint64_t y05 = uu____7 & (uint64_t)0x1111111111111111U;
  uint64_t y115 = uu____7 & (uint64_t)0x2222222222222222U;
  uint64_t y215 = uu____7 & (uint64_t)0x4444444444444444U;
  uint64_t y325 = uu____7 & (uint64_t)0x8888888888888888U;
  uint64_t z014 = x05 * y05 ^ (x115 * y325 ^ (x215 * y215 ^ x315 * y115));
  uint64_t z113 = x05 * y115 ^ (x115 * y05 ^ (x215 * y325 ^ x315 * y215));
  uint64_t z212 = x05 * y215 ^ (x115 * y115 ^ (x215 * y05 ^ x315 * y325));
  uint64_t z37 = x05 * y325 ^ (x115 * y215 ^ (x215 * y115 ^ x315 * y05));
  uint64_t
  z2h =
    (((z014 & (uint64_t)0x1111111111111111U) | (z113 & (uint64_t)0x2222222222222222U))
    | (z212 & (uint64_t)0x4444444444444444U))
    | (z37 & (uint64_t)0x8888888888888888U);
  uint64_t z213 = z26 ^ (z02 ^ z15);
  uint64_t z2h10 = z2h ^ (z0h ^ z1h);
  uint64_t
  x52 =
    (z0h & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z0h >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x61 =
    (x52 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x52 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x71 =
    (x61 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x61 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x81 =
    (x71 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x71 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x91 =
    (x81 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x81 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z0h1 = (x91 << (uint32_t)32U | x91 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x53 =
    (z1h & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z1h >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x62 =
    (x53 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x53 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x72 =
    (x62 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x62 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x82 =
    (x72 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x72 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x92 =
    (x82 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x82 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z1h1 = (x92 << (uint32_t)32U | x92 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x54 =
    (z2h10 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z2h10 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x63 =
    (x54 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x54 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x73 =
    (x63 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x63 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x83 =
    (x73 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x73 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x93 =
    (x83 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x83 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z2h2 = (x93 << (uint32_t)32U | x93 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t z1_1 = z02;
  uint64_t z1_2 = z0h1 ^ z213;
  uint64_t z1_3 = z15 ^ z2h2;
  uint64_t z1_4 = z1h1;
  uint64_t uu____8 = x2[0U];
  uint64_t uu____9 = x2[1U];
  uint64_t uu____10 = y2[0U];
  uint64_t uu____11 = y2[1U];
  uint64_t uu____12 = y2[0U] ^ y2[1U];
  uint64_t uu____13 = yr2[0U];
  uint64_t uu____14 = yr2[1U];
  uint64_t uu____15 = yr2[0U] ^ yr2[1U];
  uint64_t
  x55 =
    (uu____8 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____8 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x64 =
    (x55 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x55 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x74 =
    (x64 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x64 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x84 =
    (x74 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x74 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x94 =
    (x84 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x84 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y1r0 = x94 << (uint32_t)32U | x94 >> (uint32_t)32U;
  uint64_t
  x56 =
    (uu____9 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____9 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x65 =
    (x56 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x56 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x75 =
    (x65 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x65 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x85 =
    (x75 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x75 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x95 =
    (x85 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x85 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y2r0 = x95 << (uint32_t)32U | x95 >> (uint32_t)32U;
  uint64_t y311 = uu____8 ^ uu____9;
  uint64_t y3r1 = y1r0 ^ y2r0;
  uint64_t x06 = uu____8 & (uint64_t)0x1111111111111111U;
  uint64_t x116 = uu____8 & (uint64_t)0x2222222222222222U;
  uint64_t x216 = uu____8 & (uint64_t)0x4444444444444444U;
  uint64_t x316 = uu____8 & (uint64_t)0x8888888888888888U;
  uint64_t y06 = uu____10 & (uint64_t)0x1111111111111111U;
  uint64_t y116 = uu____10 & (uint64_t)0x2222222222222222U;
  uint64_t y216 = uu____10 & (uint64_t)0x4444444444444444U;
  uint64_t y326 = uu____10 & (uint64_t)0x8888888888888888U;
  uint64_t z03 = x06 * y06 ^ (x116 * y326 ^ (x216 * y216 ^ x316 * y116));
  uint64_t z16 = x06 * y116 ^ (x116 * y06 ^ (x216 * y326 ^ x316 * y216));
  uint64_t z27 = x06 * y216 ^ (x116 * y116 ^ (x216 * y06 ^ x316 * y326));
  uint64_t z38 = x06 * y326 ^ (x116 * y216 ^ (x216 * y116 ^ x316 * y06));
  uint64_t
  z04 =
    (((z03 & (uint64_t)0x1111111111111111U) | (z16 & (uint64_t)0x2222222222222222U))
    | (z27 & (uint64_t)0x4444444444444444U))
    | (z38 & (uint64_t)0x8888888888888888U);
  uint64_t x07 = uu____9 & (uint64_t)0x1111111111111111U;
  uint64_t x117 = uu____9 & (uint64_t)0x2222222222222222U;
  uint64_t x217 = uu____9 & (uint64_t)0x4444444444444444U;
  uint64_t x317 = uu____9 & (uint64_t)0x8888888888888888U;
  uint64_t y07 = uu____11 & (uint64_t)0x1111111111111111U;
  uint64_t y117 = uu____11 & (uint64_t)0x2222222222222222U;
  uint64_t y217 = uu____11 & (uint64_t)0x4444444444444444U;
  uint64_t y327 = uu____11 & (uint64_t)0x8888888888888888U;
  uint64_t z015 = x07 * y07 ^ (x117 * y327 ^ (x217 * y217 ^ x317 * y117));
  uint64_t z17 = x07 * y117 ^ (x117 * y07 ^ (x217 * y327 ^ x317 * y217));
  uint64_t z28 = x07 * y217 ^ (x117 * y117 ^ (x217 * y07 ^ x317 * y327));
  uint64_t z39 = x07 * y327 ^ (x117 * y217 ^ (x217 * y117 ^ x317 * y07));
  uint64_t
  z18 =
    (((z015 & (uint64_t)0x1111111111111111U) | (z17 & (uint64_t)0x2222222222222222U))
    | (z28 & (uint64_t)0x4444444444444444U))
    | (z39 & (uint64_t)0x8888888888888888U);
  uint64_t x08 = y311 & (uint64_t)0x1111111111111111U;
  uint64_t x118 = y311 & (uint64_t)0x2222222222222222U;
  uint64_t x218 = y311 & (uint64_t)0x4444444444444444U;
  uint64_t x318 = y311 & (uint64_t)0x8888888888888888U;
  uint64_t y08 = uu____12 & (uint64_t)0x1111111111111111U;
  uint64_t y118 = uu____12 & (uint64_t)0x2222222222222222U;
  uint64_t y218 = uu____12 & (uint64_t)0x4444444444444444U;
  uint64_t y328 = uu____12 & (uint64_t)0x8888888888888888U;
  uint64_t z016 = x08 * y08 ^ (x118 * y328 ^ (x218 * y218 ^ x318 * y118));
  uint64_t z114 = x08 * y118 ^ (x118 * y08 ^ (x218 * y328 ^ x318 * y218));
  uint64_t z29 = x08 * y218 ^ (x118 * y118 ^ (x218 * y08 ^ x318 * y328));
  uint64_t z310 = x08 * y328 ^ (x118 * y218 ^ (x218 * y118 ^ x318 * y08));
  uint64_t
  z214 =
    (((z016 & (uint64_t)0x1111111111111111U) | (z114 & (uint64_t)0x2222222222222222U))
    | (z29 & (uint64_t)0x4444444444444444U))
    | (z310 & (uint64_t)0x8888888888888888U);
  uint64_t x09 = y1r0 & (uint64_t)0x1111111111111111U;
  uint64_t x119 = y1r0 & (uint64_t)0x2222222222222222U;
  uint64_t x219 = y1r0 & (uint64_t)0x4444444444444444U;
  uint64_t x319 = y1r0 & (uint64_t)0x8888888888888888U;
  uint64_t y09 = uu____13 & (uint64_t)0x1111111111111111U;
  uint64_t y119 = uu____13 & (uint64_t)0x2222222222222222U;
  uint64_t y219 = uu____13 & (uint64_t)0x4444444444444444U;
  uint64_t y329 = uu____13 & (uint64_t)0x8888888888888888U;
  uint64_t z017 = x09 * y09 ^ (x119 * y329 ^ (x219 * y219 ^ x319 * y119));
  uint64_t z115 = x09 * y119 ^ (x119 * y09 ^ (x219 * y329 ^ x319 * y219));
  uint64_t z215 = x09 * y219 ^ (x119 * y119 ^ (x219 * y09 ^ x319 * y329));
  uint64_t z311 = x09 * y329 ^ (x119 * y219 ^ (x219 * y119 ^ x319 * y09));
  uint64_t
  z0h0 =
    (((z017 & (uint64_t)0x1111111111111111U) | (z115 & (uint64_t)0x2222222222222222U))
    | (z215 & (uint64_t)0x4444444444444444U))
    | (z311 & (uint64_t)0x8888888888888888U);
  uint64_t x010 = y2r0 & (uint64_t)0x1111111111111111U;
  uint64_t x1110 = y2r0 & (uint64_t)0x2222222222222222U;
  uint64_t x2110 = y2r0 & (uint64_t)0x4444444444444444U;
  uint64_t x3110 = y2r0 & (uint64_t)0x8888888888888888U;
  uint64_t y010 = uu____14 & (uint64_t)0x1111111111111111U;
  uint64_t y1110 = uu____14 & (uint64_t)0x2222222222222222U;
  uint64_t y2110 = uu____14 & (uint64_t)0x4444444444444444U;
  uint64_t y3210 = uu____14 & (uint64_t)0x8888888888888888U;
  uint64_t z018 = x010 * y010 ^ (x1110 * y3210 ^ (x2110 * y2110 ^ x3110 * y1110));
  uint64_t z116 = x010 * y1110 ^ (x1110 * y010 ^ (x2110 * y3210 ^ x3110 * y2110));
  uint64_t z216 = x010 * y2110 ^ (x1110 * y1110 ^ (x2110 * y010 ^ x3110 * y3210));
  uint64_t z312 = x010 * y3210 ^ (x1110 * y2110 ^ (x2110 * y1110 ^ x3110 * y010));
  uint64_t
  z1h0 =
    (((z018 & (uint64_t)0x1111111111111111U) | (z116 & (uint64_t)0x2222222222222222U))
    | (z216 & (uint64_t)0x4444444444444444U))
    | (z312 & (uint64_t)0x8888888888888888U);
  uint64_t x011 = y3r1 & (uint64_t)0x1111111111111111U;
  uint64_t x1111 = y3r1 & (uint64_t)0x2222222222222222U;
  uint64_t x2111 = y3r1 & (uint64_t)0x4444444444444444U;
  uint64_t x3111 = y3r1 & (uint64_t)0x8888888888888888U;
  uint64_t y011 = uu____15 & (uint64_t)0x1111111111111111U;
  uint64_t y1111 = uu____15 & (uint64_t)0x2222222222222222U;
  uint64_t y2111 = uu____15 & (uint64_t)0x4444444444444444U;
  uint64_t y3211 = uu____15 & (uint64_t)0x8888888888888888U;
  uint64_t z019 = x011 * y011 ^ (x1111 * y3211 ^ (x2111 * y2111 ^ x3111 * y1111));
  uint64_t z117 = x011 * y1111 ^ (x1111 * y011 ^ (x2111 * y3211 ^ x3111 * y2111));
  uint64_t z217 = x011 * y2111 ^ (x1111 * y1111 ^ (x2111 * y011 ^ x3111 * y3211));
  uint64_t z313 = x011 * y3211 ^ (x1111 * y2111 ^ (x2111 * y1111 ^ x3111 * y011));
  uint64_t
  z2h0 =
    (((z019 & (uint64_t)0x1111111111111111U) | (z117 & (uint64_t)0x2222222222222222U))
    | (z217 & (uint64_t)0x4444444444444444U))
    | (z313 & (uint64_t)0x8888888888888888U);
  uint64_t z218 = z214 ^ (z04 ^ z18);
  uint64_t z2h11 = z2h0 ^ (z0h0 ^ z1h0);
  uint64_t
  x57 =
    (z0h0 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z0h0 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x66 =
    (x57 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x57 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x76 =
    (x66 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x66 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x86 =
    (x76 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x76 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x96 =
    (x86 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x86 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z0h10 = (x96 << (uint32_t)32U | x96 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x58 =
    (z1h0 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z1h0 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x67 =
    (x58 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x58 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x77 =
    (x67 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x67 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x87 =
    (x77 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x77 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x97 =
    (x87 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x87 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z1h10 = (x97 << (uint32_t)32U | x97 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x59 =
    (z2h11 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z2h11 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x68 =
    (x59 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x59 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x78 =
    (x68 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x68 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x88 =
    (x78 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x78 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x98 =
    (x88 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x88 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z2h20 = (x98 << (uint32_t)32U | x98 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t z2_1 = z04;
  uint64_t z2_2 = z0h10 ^ z218;
  uint64_t z2_3 = z18 ^ z2h20;
  uint64_t z2_4 = z1h10;
  uint64_t z1 = z1_1 ^ z2_1;
  uint64_t z2 = z1_2 ^ z2_2;
  uint64_t z3 = z1_3 ^ z2_3;
  uint64_t z4 = z1_4 ^ z2_4;
  uint64_t uu____16 = x3[0U];
  uint64_t uu____17 = x3[1U];
  uint64_t uu____18 = y3[0U];
  uint64_t uu____19 = y3[1U];
  uint64_t uu____20 = y3[0U] ^ y3[1U];
  uint64_t uu____21 = yr3[0U];
  uint64_t uu____22 = yr3[1U];
  uint64_t uu____23 = yr3[0U] ^ yr3[1U];
  uint64_t
  x510 =
    (uu____16 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____16 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x69 =
    (x510 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x510 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x79 =
    (x69 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x69 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x89 =
    (x79 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x79 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x99 =
    (x89 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x89 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y1r1 = x99 << (uint32_t)32U | x99 >> (uint32_t)32U;
  uint64_t
  x511 =
    (uu____17 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____17 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x610 =
    (x511 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x511 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x710 =
    (x610 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x610 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x810 =
    (x710 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x710 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x910 =
    (x810 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x810 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y2r1 = x910 << (uint32_t)32U | x910 >> (uint32_t)32U;
  uint64_t y312 = uu____16 ^ uu____17;
  uint64_t y3r2 = y1r1 ^ y2r1;
  uint64_t x012 = uu____16 & (uint64_t)0x1111111111111111U;
  uint64_t x1112 = uu____16 & (uint64_t)0x2222222222222222U;
  uint64_t x2112 = uu____16 & (uint64_t)0x4444444444444444U;
  uint64_t x3112 = uu____16 & (uint64_t)0x8888888888888888U;
  uint64_t y012 = uu____18 & (uint64_t)0x1111111111111111U;
  uint64_t y1112 = uu____18 & (uint64_t)0x2222222222222222U;
  uint64_t y2112 = uu____18 & (uint64_t)0x4444444444444444U;
  uint64_t y3212 = uu____18 & (uint64_t)0x8888888888888888U;
  uint64_t z05 = x012 * y012 ^ (x1112 * y3212 ^ (x2112 * y2112 ^ x3112 * y1112));
  uint64_t z118 = x012 * y1112 ^ (x1112 * y012 ^ (x2112 * y3212 ^ x3112 * y2112));
  uint64_t z219 = x012 * y2112 ^ (x1112 * y1112 ^ (x2112 * y012 ^ x3112 * y3212));
  uint64_t z314 = x012 * y3212 ^ (x1112 * y2112 ^ (x2112 * y1112 ^ x3112 * y012));
  uint64_t
  z06 =
    (((z05 & (uint64_t)0x1111111111111111U) | (z118 & (uint64_t)0x2222222222222222U))
    | (z219 & (uint64_t)0x4444444444444444U))
    | (z314 & (uint64_t)0x8888888888888888U);
  uint64_t x013 = uu____17 & (uint64_t)0x1111111111111111U;
  uint64_t x1113 = uu____17 & (uint64_t)0x2222222222222222U;
  uint64_t x2113 = uu____17 & (uint64_t)0x4444444444444444U;
  uint64_t x3113 = uu____17 & (uint64_t)0x8888888888888888U;
  uint64_t y013 = uu____19 & (uint64_t)0x1111111111111111U;
  uint64_t y1113 = uu____19 & (uint64_t)0x2222222222222222U;
  uint64_t y2113 = uu____19 & (uint64_t)0x4444444444444444U;
  uint64_t y3213 = uu____19 & (uint64_t)0x8888888888888888U;
  uint64_t z0110 = x013 * y013 ^ (x1113 * y3213 ^ (x2113 * y2113 ^ x3113 * y1113));
  uint64_t z119 = x013 * y1113 ^ (x1113 * y013 ^ (x2113 * y3213 ^ x3113 * y2113));
  uint64_t z2110 = x013 * y2113 ^ (x1113 * y1113 ^ (x2113 * y013 ^ x3113 * y3213));
  uint64_t z315 = x013 * y3213 ^ (x1113 * y2113 ^ (x2113 * y1113 ^ x3113 * y013));
  uint64_t
  z1110 =
    (((z0110 & (uint64_t)0x1111111111111111U) | (z119 & (uint64_t)0x2222222222222222U))
    | (z2110 & (uint64_t)0x4444444444444444U))
    | (z315 & (uint64_t)0x8888888888888888U);
  uint64_t x014 = y312 & (uint64_t)0x1111111111111111U;
  uint64_t x1114 = y312 & (uint64_t)0x2222222222222222U;
  uint64_t x2114 = y312 & (uint64_t)0x4444444444444444U;
  uint64_t x3114 = y312 & (uint64_t)0x8888888888888888U;
  uint64_t y014 = uu____20 & (uint64_t)0x1111111111111111U;
  uint64_t y1114 = uu____20 & (uint64_t)0x2222222222222222U;
  uint64_t y2114 = uu____20 & (uint64_t)0x4444444444444444U;
  uint64_t y3214 = uu____20 & (uint64_t)0x8888888888888888U;
  uint64_t z0111 = x014 * y014 ^ (x1114 * y3214 ^ (x2114 * y2114 ^ x3114 * y1114));
  uint64_t z120 = x014 * y1114 ^ (x1114 * y014 ^ (x2114 * y3214 ^ x3114 * y2114));
  uint64_t z2111 = x014 * y2114 ^ (x1114 * y1114 ^ (x2114 * y014 ^ x3114 * y3214));
  uint64_t z316 = x014 * y3214 ^ (x1114 * y2114 ^ (x2114 * y1114 ^ x3114 * y014));
  uint64_t
  z2112 =
    (((z0111 & (uint64_t)0x1111111111111111U) | (z120 & (uint64_t)0x2222222222222222U))
    | (z2111 & (uint64_t)0x4444444444444444U))
    | (z316 & (uint64_t)0x8888888888888888U);
  uint64_t x015 = y1r1 & (uint64_t)0x1111111111111111U;
  uint64_t x1115 = y1r1 & (uint64_t)0x2222222222222222U;
  uint64_t x2115 = y1r1 & (uint64_t)0x4444444444444444U;
  uint64_t x3115 = y1r1 & (uint64_t)0x8888888888888888U;
  uint64_t y015 = uu____21 & (uint64_t)0x1111111111111111U;
  uint64_t y1115 = uu____21 & (uint64_t)0x2222222222222222U;
  uint64_t y2115 = uu____21 & (uint64_t)0x4444444444444444U;
  uint64_t y3215 = uu____21 & (uint64_t)0x8888888888888888U;
  uint64_t z0112 = x015 * y015 ^ (x1115 * y3215 ^ (x2115 * y2115 ^ x3115 * y1115));
  uint64_t z121 = x015 * y1115 ^ (x1115 * y015 ^ (x2115 * y3215 ^ x3115 * y2115));
  uint64_t z220 = x015 * y2115 ^ (x1115 * y1115 ^ (x2115 * y015 ^ x3115 * y3215));
  uint64_t z317 = x015 * y3215 ^ (x1115 * y2115 ^ (x2115 * y1115 ^ x3115 * y015));
  uint64_t
  z0h2 =
    (((z0112 & (uint64_t)0x1111111111111111U) | (z121 & (uint64_t)0x2222222222222222U))
    | (z220 & (uint64_t)0x4444444444444444U))
    | (z317 & (uint64_t)0x8888888888888888U);
  uint64_t x016 = y2r1 & (uint64_t)0x1111111111111111U;
  uint64_t x1116 = y2r1 & (uint64_t)0x2222222222222222U;
  uint64_t x2116 = y2r1 & (uint64_t)0x4444444444444444U;
  uint64_t x3116 = y2r1 & (uint64_t)0x8888888888888888U;
  uint64_t y016 = uu____22 & (uint64_t)0x1111111111111111U;
  uint64_t y1116 = uu____22 & (uint64_t)0x2222222222222222U;
  uint64_t y2116 = uu____22 & (uint64_t)0x4444444444444444U;
  uint64_t y3216 = uu____22 & (uint64_t)0x8888888888888888U;
  uint64_t z0113 = x016 * y016 ^ (x1116 * y3216 ^ (x2116 * y2116 ^ x3116 * y1116));
  uint64_t z122 = x016 * y1116 ^ (x1116 * y016 ^ (x2116 * y3216 ^ x3116 * y2116));
  uint64_t z221 = x016 * y2116 ^ (x1116 * y1116 ^ (x2116 * y016 ^ x3116 * y3216));
  uint64_t z318 = x016 * y3216 ^ (x1116 * y2116 ^ (x2116 * y1116 ^ x3116 * y016));
  uint64_t
  z1h2 =
    (((z0113 & (uint64_t)0x1111111111111111U) | (z122 & (uint64_t)0x2222222222222222U))
    | (z221 & (uint64_t)0x4444444444444444U))
    | (z318 & (uint64_t)0x8888888888888888U);
  uint64_t x017 = y3r2 & (uint64_t)0x1111111111111111U;
  uint64_t x1117 = y3r2 & (uint64_t)0x2222222222222222U;
  uint64_t x2117 = y3r2 & (uint64_t)0x4444444444444444U;
  uint64_t x3117 = y3r2 & (uint64_t)0x8888888888888888U;
  uint64_t y017 = uu____23 & (uint64_t)0x1111111111111111U;
  uint64_t y1117 = uu____23 & (uint64_t)0x2222222222222222U;
  uint64_t y2117 = uu____23 & (uint64_t)0x4444444444444444U;
  uint64_t y3217 = uu____23 & (uint64_t)0x8888888888888888U;
  uint64_t z0114 = x017 * y017 ^ (x1117 * y3217 ^ (x2117 * y2117 ^ x3117 * y1117));
  uint64_t z123 = x017 * y1117 ^ (x1117 * y017 ^ (x2117 * y3217 ^ x3117 * y2117));
  uint64_t z222 = x017 * y2117 ^ (x1117 * y1117 ^ (x2117 * y017 ^ x3117 * y3217));
  uint64_t z319 = x017 * y3217 ^ (x1117 * y2117 ^ (x2117 * y1117 ^ x3117 * y017));
  uint64_t
  z2h3 =
    (((z0114 & (uint64_t)0x1111111111111111U) | (z123 & (uint64_t)0x2222222222222222U))
    | (z222 & (uint64_t)0x4444444444444444U))
    | (z319 & (uint64_t)0x8888888888888888U);
  uint64_t z223 = z2112 ^ (z06 ^ z1110);
  uint64_t z2h12 = z2h3 ^ (z0h2 ^ z1h2);
  uint64_t
  x512 =
    (z0h2 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z0h2 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x611 =
    (x512 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x512 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x711 =
    (x611 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x611 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x811 =
    (x711 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x711 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x911 =
    (x811 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x811 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z0h11 = (x911 << (uint32_t)32U | x911 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x513 =
    (z1h2 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z1h2 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x612 =
    (x513 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x513 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x712 =
    (x612 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x612 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x812 =
    (x712 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x712 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x912 =
    (x812 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x812 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z1h11 = (x912 << (uint32_t)32U | x912 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x514 =
    (z2h12 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z2h12 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x613 =
    (x514 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x514 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x713 =
    (x613 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x613 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x813 =
    (x713 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x713 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x913 =
    (x813 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x813 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z2h21 = (x913 << (uint32_t)32U | x913 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t z3_1 = z06;
  uint64_t z3_2 = z0h11 ^ z223;
  uint64_t z3_3 = z1110 ^ z2h21;
  uint64_t z3_4 = z1h11;
  uint64_t z11 = z1 ^ z3_1;
  uint64_t z21 = z2 ^ z3_2;
  uint64_t z31 = z3 ^ z3_3;
  uint64_t z41 = z4 ^ z3_4;
  uint64_t uu____24 = x4[0U];
  uint64_t uu____25 = x4[1U];
  uint64_t uu____26 = y4[0U];
  uint64_t uu____27 = y4[1U];
  uint64_t uu____28 = y4[0U] ^ y4[1U];
  uint64_t uu____29 = yr4[0U];
  uint64_t uu____30 = yr4[1U];
  uint64_t uu____31 = yr4[0U] ^ yr4[1U];
  uint64_t
  x515 =
    (uu____24 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____24 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x614 =
    (x515 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x515 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x714 =
    (x614 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x614 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x814 =
    (x714 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x714 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x914 =
    (x814 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x814 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y1r2 = x914 << (uint32_t)32U | x914 >> (uint32_t)32U;
  uint64_t
  x516 =
    (uu____25 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (uu____25 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x615 =
    (x516 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x516 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x715 =
    (x615 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x615 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x815 =
    (x715 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x715 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x915 =
    (x815 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x815 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t y2r2 = x915 << (uint32_t)32U | x915 >> (uint32_t)32U;
  uint64_t y31 = uu____24 ^ uu____25;
  uint64_t y3r = y1r2 ^ y2r2;
  uint64_t x018 = uu____24 & (uint64_t)0x1111111111111111U;
  uint64_t x1118 = uu____24 & (uint64_t)0x2222222222222222U;
  uint64_t x2118 = uu____24 & (uint64_t)0x4444444444444444U;
  uint64_t x3118 = uu____24 & (uint64_t)0x8888888888888888U;
  uint64_t y018 = uu____26 & (uint64_t)0x1111111111111111U;
  uint64_t y1118 = uu____26 & (uint64_t)0x2222222222222222U;
  uint64_t y2118 = uu____26 & (uint64_t)0x4444444444444444U;
  uint64_t y3218 = uu____26 & (uint64_t)0x8888888888888888U;
  uint64_t z0 = x018 * y018 ^ (x1118 * y3218 ^ (x2118 * y2118 ^ x3118 * y1118));
  uint64_t z124 = x018 * y1118 ^ (x1118 * y018 ^ (x2118 * y3218 ^ x3118 * y2118));
  uint64_t z224 = x018 * y2118 ^ (x1118 * y1118 ^ (x2118 * y018 ^ x3118 * y3218));
  uint64_t z320 = x018 * y3218 ^ (x1118 * y2118 ^ (x2118 * y1118 ^ x3118 * y018));
  uint64_t
  z07 =
    (((z0 & (uint64_t)0x1111111111111111U) | (z124 & (uint64_t)0x2222222222222222U))
    | (z224 & (uint64_t)0x4444444444444444U))
    | (z320 & (uint64_t)0x8888888888888888U);
  uint64_t x019 = uu____25 & (uint64_t)0x1111111111111111U;
  uint64_t x1119 = uu____25 & (uint64_t)0x2222222222222222U;
  uint64_t x2119 = uu____25 & (uint64_t)0x4444444444444444U;
  uint64_t x3119 = uu____25 & (uint64_t)0x8888888888888888U;
  uint64_t y019 = uu____27 & (uint64_t)0x1111111111111111U;
  uint64_t y1119 = uu____27 & (uint64_t)0x2222222222222222U;
  uint64_t y2119 = uu____27 & (uint64_t)0x4444444444444444U;
  uint64_t y3219 = uu____27 & (uint64_t)0x8888888888888888U;
  uint64_t z0115 = x019 * y019 ^ (x1119 * y3219 ^ (x2119 * y2119 ^ x3119 * y1119));
  uint64_t z125 = x019 * y1119 ^ (x1119 * y019 ^ (x2119 * y3219 ^ x3119 * y2119));
  uint64_t z225 = x019 * y2119 ^ (x1119 * y1119 ^ (x2119 * y019 ^ x3119 * y3219));
  uint64_t z321 = x019 * y3219 ^ (x1119 * y2119 ^ (x2119 * y1119 ^ x3119 * y019));
  uint64_t
  z126 =
    (((z0115 & (uint64_t)0x1111111111111111U) | (z125 & (uint64_t)0x2222222222222222U))
    | (z225 & (uint64_t)0x4444444444444444U))
    | (z321 & (uint64_t)0x8888888888888888U);
  uint64_t x020 = y31 & (uint64_t)0x1111111111111111U;
  uint64_t x1120 = y31 & (uint64_t)0x2222222222222222U;
  uint64_t x2120 = y31 & (uint64_t)0x4444444444444444U;
  uint64_t x3120 = y31 & (uint64_t)0x8888888888888888U;
  uint64_t y020 = uu____28 & (uint64_t)0x1111111111111111U;
  uint64_t y1120 = uu____28 & (uint64_t)0x2222222222222222U;
  uint64_t y2120 = uu____28 & (uint64_t)0x4444444444444444U;
  uint64_t y3220 = uu____28 & (uint64_t)0x8888888888888888U;
  uint64_t z0116 = x020 * y020 ^ (x1120 * y3220 ^ (x2120 * y2120 ^ x3120 * y1120));
  uint64_t z130 = x020 * y1120 ^ (x1120 * y020 ^ (x2120 * y3220 ^ x3120 * y2120));
  uint64_t z226 = x020 * y2120 ^ (x1120 * y1120 ^ (x2120 * y020 ^ x3120 * y3220));
  uint64_t z322 = x020 * y3220 ^ (x1120 * y2120 ^ (x2120 * y1120 ^ x3120 * y020));
  uint64_t
  z227 =
    (((z0116 & (uint64_t)0x1111111111111111U) | (z130 & (uint64_t)0x2222222222222222U))
    | (z226 & (uint64_t)0x4444444444444444U))
    | (z322 & (uint64_t)0x8888888888888888U);
  uint64_t x021 = y1r2 & (uint64_t)0x1111111111111111U;
  uint64_t x1121 = y1r2 & (uint64_t)0x2222222222222222U;
  uint64_t x2121 = y1r2 & (uint64_t)0x4444444444444444U;
  uint64_t x3121 = y1r2 & (uint64_t)0x8888888888888888U;
  uint64_t y021 = uu____29 & (uint64_t)0x1111111111111111U;
  uint64_t y1121 = uu____29 & (uint64_t)0x2222222222222222U;
  uint64_t y2121 = uu____29 & (uint64_t)0x4444444444444444U;
  uint64_t y3221 = uu____29 & (uint64_t)0x8888888888888888U;
  uint64_t z0117 = x021 * y021 ^ (x1121 * y3221 ^ (x2121 * y2121 ^ x3121 * y1121));
  uint64_t z131 = x021 * y1121 ^ (x1121 * y021 ^ (x2121 * y3221 ^ x3121 * y2121));
  uint64_t z230 = x021 * y2121 ^ (x1121 * y1121 ^ (x2121 * y021 ^ x3121 * y3221));
  uint64_t z323 = x021 * y3221 ^ (x1121 * y2121 ^ (x2121 * y1121 ^ x3121 * y021));
  uint64_t
  z0h3 =
    (((z0117 & (uint64_t)0x1111111111111111U) | (z131 & (uint64_t)0x2222222222222222U))
    | (z230 & (uint64_t)0x4444444444444444U))
    | (z323 & (uint64_t)0x8888888888888888U);
  uint64_t x022 = y2r2 & (uint64_t)0x1111111111111111U;
  uint64_t x1122 = y2r2 & (uint64_t)0x2222222222222222U;
  uint64_t x2122 = y2r2 & (uint64_t)0x4444444444444444U;
  uint64_t x3122 = y2r2 & (uint64_t)0x8888888888888888U;
  uint64_t y022 = uu____30 & (uint64_t)0x1111111111111111U;
  uint64_t y1122 = uu____30 & (uint64_t)0x2222222222222222U;
  uint64_t y2122 = uu____30 & (uint64_t)0x4444444444444444U;
  uint64_t y3222 = uu____30 & (uint64_t)0x8888888888888888U;
  uint64_t z0118 = x022 * y022 ^ (x1122 * y3222 ^ (x2122 * y2122 ^ x3122 * y1122));
  uint64_t z132 = x022 * y1122 ^ (x1122 * y022 ^ (x2122 * y3222 ^ x3122 * y2122));
  uint64_t z231 = x022 * y2122 ^ (x1122 * y1122 ^ (x2122 * y022 ^ x3122 * y3222));
  uint64_t z324 = x022 * y3222 ^ (x1122 * y2122 ^ (x2122 * y1122 ^ x3122 * y022));
  uint64_t
  z1h3 =
    (((z0118 & (uint64_t)0x1111111111111111U) | (z132 & (uint64_t)0x2222222222222222U))
    | (z231 & (uint64_t)0x4444444444444444U))
    | (z324 & (uint64_t)0x8888888888888888U);
  uint64_t x0 = y3r & (uint64_t)0x1111111111111111U;
  uint64_t x11 = y3r & (uint64_t)0x2222222222222222U;
  uint64_t x21 = y3r & (uint64_t)0x4444444444444444U;
  uint64_t x31 = y3r & (uint64_t)0x8888888888888888U;
  uint64_t y0 = uu____31 & (uint64_t)0x1111111111111111U;
  uint64_t y11 = uu____31 & (uint64_t)0x2222222222222222U;
  uint64_t y21 = uu____31 & (uint64_t)0x4444444444444444U;
  uint64_t y32 = uu____31 & (uint64_t)0x8888888888888888U;
  uint64_t z01 = x0 * y0 ^ (x11 * y32 ^ (x21 * y21 ^ x31 * y11));
  uint64_t z13 = x0 * y11 ^ (x11 * y0 ^ (x21 * y32 ^ x31 * y21));
  uint64_t z232 = x0 * y21 ^ (x11 * y11 ^ (x21 * y0 ^ x31 * y32));
  uint64_t z325 = x0 * y32 ^ (x11 * y21 ^ (x21 * y11 ^ x31 * y0));
  uint64_t
  z2h4 =
    (((z01 & (uint64_t)0x1111111111111111U) | (z13 & (uint64_t)0x2222222222222222U))
    | (z232 & (uint64_t)0x4444444444444444U))
    | (z325 & (uint64_t)0x8888888888888888U);
  uint64_t z23 = z227 ^ (z07 ^ z126);
  uint64_t z2h1 = z2h4 ^ (z0h3 ^ z1h3);
  uint64_t
  x517 =
    (z0h3 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z0h3 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x616 =
    (x517 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x517 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x716 =
    (x616 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x616 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x816 =
    (x716 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x716 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x916 =
    (x816 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x816 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z0h12 = (x916 << (uint32_t)32U | x916 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x518 =
    (z1h3 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z1h3 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x617 =
    (x518 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x518 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x717 =
    (x617 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x617 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x817 =
    (x717 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x717 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x917 =
    (x817 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x817 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z1h12 = (x917 << (uint32_t)32U | x917 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t
  x5 =
    (z2h1 & (uint64_t)0x5555555555555555U)
    << (uint32_t)(uint8_t)1U
    | (z2h1 >> (uint32_t)(uint8_t)1U & (uint64_t)0x5555555555555555U);
  uint64_t
  x618 =
    (x5 & (uint64_t)0x3333333333333333U)
    << (uint32_t)(uint8_t)2U
    | (x5 >> (uint32_t)(uint8_t)2U & (uint64_t)0x3333333333333333U);
  uint64_t
  x718 =
    (x618 & (uint64_t)0x0F0F0F0F0F0F0F0FU)
    << (uint32_t)(uint8_t)4U
    | (x618 >> (uint32_t)(uint8_t)4U & (uint64_t)0x0F0F0F0F0F0F0F0FU);
  uint64_t
  x818 =
    (x718 & (uint64_t)0x00FF00FF00FF00FFU)
    << (uint32_t)(uint8_t)8U
    | (x718 >> (uint32_t)(uint8_t)8U & (uint64_t)0x00FF00FF00FF00FFU);
  uint64_t
  x918 =
    (x818 & (uint64_t)0x0000FFFF0000FFFFU)
    << (uint32_t)(uint8_t)16U
    | (x818 >> (uint32_t)(uint8_t)16U & (uint64_t)0x0000FFFF0000FFFFU);
  uint64_t z2h22 = (x918 << (uint32_t)32U | x918 >> (uint32_t)32U) >> (uint32_t)1U;
  uint64_t z4_1 = z07;
  uint64_t z4_2 = z0h12 ^ z23;
  uint64_t z4_3 = z126 ^ z2h22;
  uint64_t z4_4 = z1h12;
  uint64_t z12 = z11 ^ z4_1;
  uint64_t z22 = z21 ^ z4_2;
  uint64_t z32 = z31 ^ z4_3;
  uint64_t z42 = z41 ^ z4_4;
  uint64_t v3 = z42 << (uint32_t)1U | z32 >> (uint32_t)63U;
  uint64_t v20 = z32 << (uint32_t)1U | z22 >> (uint32_t)63U;
  uint64_t v1 = z22 << (uint32_t)1U | z12 >> (uint32_t)63U;
  uint64_t v0 = z12 << (uint32_t)1U;
  uint64_t v21 = v20 ^ (v0 ^ (v0 >> (uint32_t)1U ^ (v0 >> (uint32_t)2U ^ v0 >> (uint32_t)7U)));
  uint64_t v11 = v1 ^ (v0 << (uint32_t)63U ^ (v0 << (uint32_t)62U ^ v0 << (uint32_t)57U));
  uint64_t
  v31 = v3 ^ (v11 ^ (v11 >> (uint32_t)1U ^ (v11 >> (uint32_t)2U ^ v11 >> (uint32_t)7U)));
  uint64_t v22 = v21 ^ (v11 << (uint32_t)63U ^ (v11 << (uint32_t)62U ^ v11 << (uint32_t)57U));
  uint64_t v10 = v22;
  uint64_t v2 = v31;
  acc[0U] = v10;
  acc[1U] = v2;
}

void Hacl_Gf128_CT64_gcm_init(uint64_t *ctx, uint8_t *key)
{
  uint64_t *acc = ctx;
  uint64_t *pre = ctx + (uint32_t)2U;
  acc[0U] = (uint64_t)0U;
  acc[1U] = (uint64_t)0U;
  load_precompute_r(pre, key);
}

void Hacl_Gf128_CT64_gcm_update_blocks(uint64_t *ctx, uint32_t len, uint8_t *text)
{
  uint64_t *acc = ctx;
  uint64_t *pre = ctx + (uint32_t)2U;
  uint32_t len0 = len / (uint32_t)64U * (uint32_t)64U;
  uint8_t *t0 = text;
  if (len0 > (uint32_t)0U)
  {
    uint64_t f[8U] = { 0U };
    uint64_t *b4 = f;
    uint32_t nb = len0 / (uint32_t)64U;
    for (uint32_t i = (uint32_t)0U; i < nb; i++)
    {
      uint8_t *tb = t0 + i * (uint32_t)64U;
      uint64_t *x0 = b4;
      uint8_t *y0 = tb;
      uint64_t *x1 = b4 + (uint32_t)2U;
      uint8_t *y1 = tb + (uint32_t)16U;
      uint64_t *x2 = b4 + (uint32_t)4U;
      uint8_t *y2 = tb + (uint32_t)32U;
      uint64_t *x3 = b4 + (uint32_t)6U;
      uint8_t *y3 = tb + (uint32_t)48U;
      uint64_t u = load64_be(y0);
      x0[1U] = u;
      uint64_t u0 = load64_be(y0 + (uint32_t)8U);
      x0[0U] = u0;
      uint64_t u1 = load64_be(y1);
      x1[1U] = u1;
      uint64_t u2 = load64_be(y1 + (uint32_t)8U);
      x1[0U] = u2;
      uint64_t u3 = load64_be(y2);
      x2[1U] = u3;
      uint64_t u4 = load64_be(y2 + (uint32_t)8U);
      x2[0U] = u4;
      uint64_t u5 = load64_be(y3);
      x3[1U] = u5;
      uint64_t u6 = load64_be(y3 + (uint32_t)8U);
      x3[0U] = u6;
      uint64_t *uu____0 = b4;
      uu____0[0U] = uu____0[0U] ^ acc[0U];
      uu____0[1U] = uu____0[1U] ^ acc[1U];
      normalize4(acc, b4, pre);
    }
  }
  uint32_t len1 = len - len0;
  uint8_t *t1 = text + len0;
  uint64_t *r1 = pre + (uint32_t)6U;
  uint32_t nb = len1 / (uint32_t)16U;
  uint32_t rem = len1 % (uint32_t)16U;
  for (uint32_t i = (uint32_t)0U; i < nb; i++)
  {
    uint8_t *tb = t1 + i * (uint32_t)16U;
    uint64_t elem[2U] = { 0U };
    uint64_t u = load64_be(tb);
    elem[1U] = u;
    uint64_t u0 = load64_be(tb + (uint32_t)8U);
    elem[0U] = u0;
    acc[0U] = acc[0U] ^ elem[0U];
    acc[1U] = acc[1U] ^ elem[1U];
    fmul0(acc, r1);
  }
  if (rem > (uint32_t)0U)
  {
    uint8_t *last = t1 + nb * (uint32_t)16U;
    uint64_t elem[2U] = { 0U };
    uint8_t b[16U] = { 0U };
    memcpy(b, last, rem * sizeof (uint8_t));
    uint64_t u = load64_be(b);
    elem[1U] = u;
    uint64_t u0 = load64_be(b + (uint32_t)8U);
    elem[0U] = u0;
    acc[0U] = acc[0U] ^ elem[0U];
    acc[1U] = acc[1U] ^ elem[1U];
    fmul0(acc, r1);
    return;
  }
}

void
(*Hacl_Gf128_CT64_gcm_update_blocks_padded)(uint64_t *x0, uint32_t x1, uint8_t *x2) =
  Hacl_Gf128_CT64_gcm_update_blocks;

void Hacl_Gf128_CT64_gcm_emit(uint8_t *tag, uint64_t *ctx)
{
  uint64_t *acc = ctx;
  uint64_t r0 = acc[1U];
  uint64_t r1 = acc[0U];
  store64_be(tag, r0);
  store64_be(tag + (uint32_t)8U, r1);
}

void Hacl_Gf128_CT64_ghash(uint8_t *tag, uint32_t len, uint8_t *text, uint8_t *key)
{
  uint64_t ctx[18U] = { 0U };
  uint64_t *acc = ctx;
  uint64_t *pre0 = ctx + (uint32_t)2U;
  acc[0U] = (uint64_t)0U;
  acc[1U] = (uint64_t)0U;
  load_precompute_r(pre0, key);
  uint64_t *acc0 = ctx;
  uint64_t *pre = ctx + (uint32_t)2U;
  uint32_t len0 = len / (uint32_t)64U * (uint32_t)64U;
  uint8_t *t0 = text;
  if (len0 > (uint32_t)0U)
  {
    uint64_t f[8U] = { 0U };
    uint64_t *b4 = f;
    uint32_t nb = len0 / (uint32_t)64U;
    for (uint32_t i = (uint32_t)0U; i < nb; i++)
    {
      uint8_t *tb = t0 + i * (uint32_t)64U;
      uint64_t *x0 = b4;
      uint8_t *y0 = tb;
      uint64_t *x1 = b4 + (uint32_t)2U;
      uint8_t *y1 = tb + (uint32_t)16U;
      uint64_t *x2 = b4 + (uint32_t)4U;
      uint8_t *y2 = tb + (uint32_t)32U;
      uint64_t *x3 = b4 + (uint32_t)6U;
      uint8_t *y3 = tb + (uint32_t)48U;
      uint64_t u = load64_be(y0);
      x0[1U] = u;
      uint64_t u0 = load64_be(y0 + (uint32_t)8U);
      x0[0U] = u0;
      uint64_t u1 = load64_be(y1);
      x1[1U] = u1;
      uint64_t u2 = load64_be(y1 + (uint32_t)8U);
      x1[0U] = u2;
      uint64_t u3 = load64_be(y2);
      x2[1U] = u3;
      uint64_t u4 = load64_be(y2 + (uint32_t)8U);
      x2[0U] = u4;
      uint64_t u5 = load64_be(y3);
      x3[1U] = u5;
      uint64_t u6 = load64_be(y3 + (uint32_t)8U);
      x3[0U] = u6;
      uint64_t *uu____0 = b4;
      uu____0[0U] = uu____0[0U] ^ acc0[0U];
      uu____0[1U] = uu____0[1U] ^ acc0[1U];
      normalize4(acc0, b4, pre);
    }
  }
  uint32_t len1 = len - len0;
  uint8_t *t1 = text + len0;
  uint64_t *r10 = pre + (uint32_t)6U;
  uint32_t nb = len1 / (uint32_t)16U;
  uint32_t rem = len1 % (uint32_t)16U;
  for (uint32_t i = (uint32_t)0U; i < nb; i++)
  {
    uint8_t *tb = t1 + i * (uint32_t)16U;
    uint64_t elem[2U] = { 0U };
    uint64_t u = load64_be(tb);
    elem[1U] = u;
    uint64_t u0 = load64_be(tb + (uint32_t)8U);
    elem[0U] = u0;
    acc0[0U] = acc0[0U] ^ elem[0U];
    acc0[1U] = acc0[1U] ^ elem[1U];
    fmul0(acc0, r10);
  }
  if (rem > (uint32_t)0U)
  {
    uint8_t *last = t1 + nb * (uint32_t)16U;
    uint64_t elem[2U] = { 0U };
    uint8_t b[16U] = { 0U };
    memcpy(b, last, rem * sizeof (uint8_t));
    uint64_t u = load64_be(b);
    elem[1U] = u;
    uint64_t u0 = load64_be(b + (uint32_t)8U);
    elem[0U] = u0;
    acc0[0U] = acc0[0U] ^ elem[0U];
    acc0[1U] = acc0[1U] ^ elem[1U];
    fmul0(acc0, r10);
  }
  uint64_t *acc1 = ctx;
  uint64_t r0 = acc1[1U];
  uint64_t r1 = acc1[0U];
  store64_be(tag, r0);
  store64_be(tag + (uint32_t)8U, r1);
}

