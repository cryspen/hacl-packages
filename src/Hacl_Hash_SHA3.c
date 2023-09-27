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


#include "internal/Hacl_Hash_SHA3.h"


static const
uint32_t
keccak_rotc[24U] =
  {
    (uint32_t)1U, (uint32_t)3U, (uint32_t)6U, (uint32_t)10U, (uint32_t)15U, (uint32_t)21U,
    (uint32_t)28U, (uint32_t)36U, (uint32_t)45U, (uint32_t)55U, (uint32_t)2U, (uint32_t)14U,
    (uint32_t)27U, (uint32_t)41U, (uint32_t)56U, (uint32_t)8U, (uint32_t)25U, (uint32_t)43U,
    (uint32_t)62U, (uint32_t)18U, (uint32_t)39U, (uint32_t)61U, (uint32_t)20U, (uint32_t)44U
  };

static const
uint32_t
keccak_piln[24U] =
  {
    (uint32_t)10U, (uint32_t)7U, (uint32_t)11U, (uint32_t)17U, (uint32_t)18U, (uint32_t)3U,
    (uint32_t)5U, (uint32_t)16U, (uint32_t)8U, (uint32_t)21U, (uint32_t)24U, (uint32_t)4U,
    (uint32_t)15U, (uint32_t)23U, (uint32_t)19U, (uint32_t)13U, (uint32_t)12U, (uint32_t)2U,
    (uint32_t)20U, (uint32_t)14U, (uint32_t)22U, (uint32_t)9U, (uint32_t)6U, (uint32_t)1U
  };

static const
uint64_t
keccak_rndc[24U] =
  {
    (uint64_t)0x0000000000000001U, (uint64_t)0x0000000000008082U, (uint64_t)0x800000000000808aU,
    (uint64_t)0x8000000080008000U, (uint64_t)0x000000000000808bU, (uint64_t)0x0000000080000001U,
    (uint64_t)0x8000000080008081U, (uint64_t)0x8000000000008009U, (uint64_t)0x000000000000008aU,
    (uint64_t)0x0000000000000088U, (uint64_t)0x0000000080008009U, (uint64_t)0x000000008000000aU,
    (uint64_t)0x000000008000808bU, (uint64_t)0x800000000000008bU, (uint64_t)0x8000000000008089U,
    (uint64_t)0x8000000000008003U, (uint64_t)0x8000000000008002U, (uint64_t)0x8000000000000080U,
    (uint64_t)0x000000000000800aU, (uint64_t)0x800000008000000aU, (uint64_t)0x8000000080008081U,
    (uint64_t)0x8000000000008080U, (uint64_t)0x0000000080000001U, (uint64_t)0x8000000080008008U
  };

static inline uint64_t CRYPTO_rotl_u64(uint64_t value, int shift) {
#if defined(_MSC_VER)
  return _rotl64(value, shift);
#else
  return (value << shift) | (value >> ((-shift) & 63));
#endif
}

static inline void Hacl_Impl_SHA3_state_permute(uint64_t *state){
   static const int kNumRounds = 24;
  for (int round = 0; round < kNumRounds; round++) {
    // θ step
    uint64_t c[5];
    for (int x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^
             state[x + 20];
    }

    for (int x = 0; x < 5; x++) {
      const uint64_t d = c[(x + 4) % 5] ^ CRYPTO_rotl_u64(c[(x + 1) % 5], 1);
      for (int y = 0; y < 5; y++) {
        state[y * 5 + x] ^= d;
      }
    }

    // ρ and π steps.
    //
    // These steps involve a mapping of the state matrix. Each input point,
    // (x,y), is rotated and written to the point (y, 2x + 3y). In the Keccak
    // pseudo-code a separate array is used because an in-place operation would
    // overwrite some values that are subsequently needed. However, the mapping
    // forms a trail through 24 of the 25 values so we can do it in place with
    // only a single temporary variable.
    //
    // Start with (1, 0). The value here will be mapped and end up at (0, 2).
    // That value will end up at (2, 1), then (1, 2), and so on. After 24
    // steps, 24 of the 25 values have been hit (as this mapping is injective)
    // and the sequence will repeat. All that remains is to handle the element
    // at (0, 0), but the rotation for that element is zero, and it goes to (0,
    // 0), so we can ignore it.
    static const uint8_t kIndexes[24] = {10, 7,  11, 17, 18, 3,  5,  16,
                                         8,  21, 24, 4,  15, 23, 19, 13,
                                         12, 2,  20, 14, 22, 9,  6,  1};
    static const uint8_t kRotations[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                           45, 55, 2,  14, 27, 41, 56, 8,
                                           25, 43, 62, 18, 39, 61, 20, 44};
    uint64_t prev_value = state[1];
    for (int i = 0; i < 24; i++) {
      const uint64_t value = CRYPTO_rotl_u64(prev_value, kRotations[i]);
      const size_t index = kIndexes[i];
      prev_value = state[index];
      state[index] = value;
    }

    // χ step
    for (int y = 0; y < 5; y++) {
      const int row_index = 5 * y;
      const uint64_t orig_x0 = state[row_index];
      const uint64_t orig_x1 = state[row_index + 1];
      state[row_index] ^= ~orig_x1 & state[row_index + 2];
      state[row_index + 1] ^= ~state[row_index + 2] & state[row_index + 3];
      state[row_index + 2] ^= ~state[row_index + 3] & state[row_index + 4];
      state[row_index + 3] ^= ~state[row_index + 4] & orig_x0;
      state[row_index + 4] ^= ~orig_x0 & orig_x1;
    }

    // ι step
    //
    // From https://keccak.team/files/Keccak-reference-3.0.pdf, section
    // 1.2, the round constants are based on the output of a LFSR. Thus, as
    // suggested in the appendix of of
    // https://keccak.team/keccak_specs_summary.html, the values are
    // simply encoded here.
    static const uint64_t kRoundConstants[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };

    state[0] ^= kRoundConstants[round];
  }
}

static inline void
Hacl_Impl_SHA3_squeeze_(
  uint64_t *s,
  uint32_t rateInBytes,
  uint32_t outputByteLen,
  uint8_t *output
)
{
  // uint32_t outBlocks = outputByteLen / rateInBytes;
  // uint32_t remOut = outputByteLen % rateInBytes;
  // uint8_t *last = output + outputByteLen - remOut;
  // uint8_t *blocks = output;
  // for (uint32_t i = (uint32_t)0U; i < outBlocks; i++)
  // {
  //   storeState(rateInBytes, s, blocks + i * rateInBytes);
  //   Hacl_Impl_SHA3_state_permute(s);
  // }
  // storeState(remOut, s, last);

  // Accessing |ctx->state| as a |uint8_t*| is allowed by strict aliasing
  // because we require |uint8_t| to be a character type.
  const uint8_t *state_bytes = (const uint8_t *)s;  
  size_t offset = 0;
  while (outputByteLen) {
    size_t remaining = rateInBytes - offset;
    size_t todo = outputByteLen;
    if (todo > remaining) {
      todo = remaining;
    }
    memcpy(output, &state_bytes[offset], todo);
    output += todo;
    outputByteLen -= todo;
    offset += todo;
    if (offset == rateInBytes) {
      Hacl_Impl_SHA3_state_permute(s);
      offset = 0;
    }
  }
}

static uint32_t block_len(Spec_Hash_Definitions_hash_alg a)
{
  switch (a)
  {
    case Spec_Hash_Definitions_SHA3_224:
      {
        return (uint32_t)144U;
      }
    case Spec_Hash_Definitions_SHA3_256:
      {
        return (uint32_t)136U;
      }
    case Spec_Hash_Definitions_SHA3_384:
      {
        return (uint32_t)104U;
      }
    case Spec_Hash_Definitions_SHA3_512:
      {
        return (uint32_t)72U;
      }
    case Spec_Hash_Definitions_Shake128:
      {
        return (uint32_t)168U;
      }
    case Spec_Hash_Definitions_Shake256:
      {
        return (uint32_t)136U;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
}

static uint32_t hash_len(Spec_Hash_Definitions_hash_alg a)
{
  switch (a)
  {
    case Spec_Hash_Definitions_SHA3_224:
      {
        return (uint32_t)28U;
      }
    case Spec_Hash_Definitions_SHA3_256:
      {
        return (uint32_t)32U;
      }
    case Spec_Hash_Definitions_SHA3_384:
      {
        return (uint32_t)48U;
      }
    case Spec_Hash_Definitions_SHA3_512:
      {
        return (uint32_t)64U;
      }
    default:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
}

static inline void Hacl_Impl_SHA3_loadState(uint32_t rateInBytes, uint8_t *input, uint64_t *s)
{
  // uint8_t block[200U] = { 0U };
  // memcpy(block, input, rateInBytes * sizeof (uint8_t));
  for (uint32_t i = (uint32_t)0U; i < (rateInBytes / 8); i++)
  {
    uint64_t u = load64_le(input + i * (uint32_t)8U);
    uint64_t x = u;
    s[i] = s[i] ^ x;
  }
}

static inline void Hacl_Impl_SHA3_absorb_inner(uint32_t rateInBytes, uint8_t *block, uint64_t *s)
{
  Hacl_Impl_SHA3_loadState(rateInBytes, block, s);
  Hacl_Impl_SHA3_state_permute(s);
}


void
Hacl_Hash_SHA3_update_multi_sha3(
  Spec_Hash_Definitions_hash_alg a,
  uint64_t *s,
  uint8_t *blocks,
  uint32_t n_blocks
)
{
  for (uint32_t i = (uint32_t)0U; i < n_blocks; i++)
  {
    uint8_t *block = blocks + i * block_len(a);
    Hacl_Impl_SHA3_absorb_inner(block_len(a), block, s);
  }
}

void
Hacl_Hash_SHA3_update_last_sha3(
  Spec_Hash_Definitions_hash_alg a,
  uint64_t *s,
  uint8_t *input,
  uint32_t input_len
)
{
  uint8_t suffix;
  if (a == Spec_Hash_Definitions_Shake128 || a == Spec_Hash_Definitions_Shake256)
  {
    suffix = (uint8_t)0x1fU;
  }
  else
  {
    suffix = (uint8_t)0x06U;
  }
  uint32_t len = block_len(a);
  if (input_len == len)
  {
    Hacl_Impl_SHA3_absorb_inner(len, input, s);
    // uint8_t *uu____0 = input + input_len;
    // uint8_t lastBlock_[200U] = { 0U };
    // uint8_t *lastBlock = lastBlock_;
    // // memcpy(lastBlock, uu____0, (uint32_t)0U * sizeof (uint8_t));
    // lastBlock[0U] = suffix;
    // Hacl_Impl_SHA3_loadState(len, lastBlock, s);
    s[0] = s[0] ^ suffix;
    if (!((suffix & (uint8_t)0x80U) == (uint8_t)0U) && (uint32_t)0U == len - (uint32_t)1U)
    {
      Hacl_Impl_SHA3_state_permute(s);
    }
    uint8_t nextBlock_[200U] = { 0U };
    uint8_t *nextBlock = nextBlock_;
    nextBlock[len - (uint32_t)1U] = (uint8_t)0x80U;
    Hacl_Impl_SHA3_loadState(len, nextBlock, s);
    Hacl_Impl_SHA3_state_permute(s);
    return;
  }
  uint8_t lastBlock_[200U] = { 0U };
  uint8_t *lastBlock = lastBlock_;
  memcpy(lastBlock, input, input_len * sizeof (uint8_t));
  lastBlock[input_len] = suffix;
  Hacl_Impl_SHA3_loadState(len, lastBlock, s);
  // s[input_len] ^= suffix;
  if (!((suffix & (uint8_t)0x80U) == (uint8_t)0U) && input_len == len - (uint32_t)1U)
  {
    Hacl_Impl_SHA3_state_permute(s);
  }
  uint8_t nextBlock_[200U] = { 0U };
  uint8_t *nextBlock = nextBlock_;
  nextBlock[len - (uint32_t)1U] = (uint8_t)0x80U;
  Hacl_Impl_SHA3_loadState(len, nextBlock, s);
  // s[len-1] ^= 0x0000000000000080;
  Hacl_Impl_SHA3_state_permute(s);
}

typedef struct hash_buf2_s
{
  Hacl_Streaming_Keccak_hash_buf fst;
  Hacl_Streaming_Keccak_hash_buf snd;
}
hash_buf2;

Spec_Hash_Definitions_hash_alg Hacl_Streaming_Keccak_get_alg(Hacl_Streaming_Keccak_state *s)
{
  Hacl_Streaming_Keccak_state scrut = *s;
  Hacl_Streaming_Keccak_hash_buf block_state = scrut.block_state;
  return block_state.fst;
}

Hacl_Streaming_Keccak_state *Hacl_Streaming_Keccak_malloc(Spec_Hash_Definitions_hash_alg a)
{
  KRML_CHECK_SIZE(sizeof (uint8_t), block_len(a));
  uint8_t *buf0 = (uint8_t *)KRML_HOST_CALLOC(block_len(a), sizeof (uint8_t));
  uint64_t *buf = (uint64_t *)KRML_HOST_CALLOC((uint32_t)25U, sizeof (uint64_t));
  Hacl_Streaming_Keccak_hash_buf block_state = { .fst = a, .snd = buf };
  Hacl_Streaming_Keccak_state
  s = { .block_state = block_state, .buf = buf0, .total_len = (uint64_t)(uint32_t)0U };
  Hacl_Streaming_Keccak_state
  *p = (Hacl_Streaming_Keccak_state *)KRML_HOST_MALLOC(sizeof (Hacl_Streaming_Keccak_state));
  p[0U] = s;
  uint64_t *s1 = block_state.snd;
  memset(s1, 0U, (uint32_t)25U * sizeof (uint64_t));
  return p;
}

void Hacl_Streaming_Keccak_free(Hacl_Streaming_Keccak_state *s)
{
  Hacl_Streaming_Keccak_state scrut = *s;
  uint8_t *buf = scrut.buf;
  Hacl_Streaming_Keccak_hash_buf block_state = scrut.block_state;
  uint64_t *s1 = block_state.snd;
  KRML_HOST_FREE(s1);
  KRML_HOST_FREE(buf);
  KRML_HOST_FREE(s);
}

Hacl_Streaming_Keccak_state *Hacl_Streaming_Keccak_copy(Hacl_Streaming_Keccak_state *s0)
{
  Hacl_Streaming_Keccak_state scrut0 = *s0;
  Hacl_Streaming_Keccak_hash_buf block_state0 = scrut0.block_state;
  uint8_t *buf0 = scrut0.buf;
  uint64_t total_len0 = scrut0.total_len;
  Spec_Hash_Definitions_hash_alg i = block_state0.fst;
  KRML_CHECK_SIZE(sizeof (uint8_t), block_len(i));
  uint8_t *buf1 = (uint8_t *)KRML_HOST_CALLOC(block_len(i), sizeof (uint8_t));
  memcpy(buf1, buf0, block_len(i) * sizeof (uint8_t));
  uint64_t *buf = (uint64_t *)KRML_HOST_CALLOC((uint32_t)25U, sizeof (uint64_t));
  Hacl_Streaming_Keccak_hash_buf block_state = { .fst = i, .snd = buf };
  hash_buf2 scrut = { .fst = block_state0, .snd = block_state };
  uint64_t *s_dst = scrut.snd.snd;
  uint64_t *s_src = scrut.fst.snd;
  memcpy(s_dst, s_src, (uint32_t)25U * sizeof (uint64_t));
  Hacl_Streaming_Keccak_state
  s = { .block_state = block_state, .buf = buf1, .total_len = total_len0 };
  Hacl_Streaming_Keccak_state
  *p = (Hacl_Streaming_Keccak_state *)KRML_HOST_MALLOC(sizeof (Hacl_Streaming_Keccak_state));
  p[0U] = s;
  return p;
}

void Hacl_Streaming_Keccak_reset(Hacl_Streaming_Keccak_state *s)
{
  Hacl_Streaming_Keccak_state scrut = *s;
  uint8_t *buf = scrut.buf;
  Hacl_Streaming_Keccak_hash_buf block_state = scrut.block_state;
  Spec_Hash_Definitions_hash_alg i = block_state.fst;
  KRML_HOST_IGNORE(i);
  uint64_t *s1 = block_state.snd;
  memset(s1, 0U, (uint32_t)25U * sizeof (uint64_t));
  Hacl_Streaming_Keccak_state
  tmp = { .block_state = block_state, .buf = buf, .total_len = (uint64_t)(uint32_t)0U };
  s[0U] = tmp;
}

Hacl_Streaming_Types_error_code
Hacl_Streaming_Keccak_update(Hacl_Streaming_Keccak_state *p, uint8_t *data, uint32_t len)
{
  Hacl_Streaming_Keccak_state s = *p;
  Hacl_Streaming_Keccak_hash_buf block_state = s.block_state;
  uint64_t total_len = s.total_len;
  Spec_Hash_Definitions_hash_alg i = block_state.fst;
  if ((uint64_t)len > (uint64_t)0xFFFFFFFFFFFFFFFFU - total_len)
  {
    return Hacl_Streaming_Types_MaximumLengthExceeded;
  }
  uint32_t sz;
  if (total_len % (uint64_t)block_len(i) == (uint64_t)0U && total_len > (uint64_t)0U)
  {
    sz = block_len(i);
  }
  else
  {
    sz = (uint32_t)(total_len % (uint64_t)block_len(i));
  }
  if (len <= block_len(i) - sz)
  {
    Hacl_Streaming_Keccak_state s1 = *p;
    Hacl_Streaming_Keccak_hash_buf block_state1 = s1.block_state;
    uint8_t *buf = s1.buf;
    uint64_t total_len1 = s1.total_len;
    uint32_t sz1;
    if (total_len1 % (uint64_t)block_len(i) == (uint64_t)0U && total_len1 > (uint64_t)0U)
    {
      sz1 = block_len(i);
    }
    else
    {
      sz1 = (uint32_t)(total_len1 % (uint64_t)block_len(i));
    }
    uint8_t *buf2 = buf + sz1;
    memcpy(buf2, data, len * sizeof (uint8_t));
    uint64_t total_len2 = total_len1 + (uint64_t)len;
    *p
    =
      (
        (Hacl_Streaming_Keccak_state){
          .block_state = block_state1,
          .buf = buf,
          .total_len = total_len2
        }
      );
  }
  else if (sz == (uint32_t)0U)
  {
    Hacl_Streaming_Keccak_state s1 = *p;
    Hacl_Streaming_Keccak_hash_buf block_state1 = s1.block_state;
    uint8_t *buf = s1.buf;
    uint64_t total_len1 = s1.total_len;
    uint32_t sz1;
    if (total_len1 % (uint64_t)block_len(i) == (uint64_t)0U && total_len1 > (uint64_t)0U)
    {
      sz1 = block_len(i);
    }
    else
    {
      sz1 = (uint32_t)(total_len1 % (uint64_t)block_len(i));
    }
    if (!(sz1 == (uint32_t)0U))
    {
      Spec_Hash_Definitions_hash_alg a1 = block_state1.fst;
      uint64_t *s2 = block_state1.snd;
      Hacl_Hash_SHA3_update_multi_sha3(a1, s2, buf, block_len(i) / block_len(a1));
    }
    uint32_t ite;
    if ((uint64_t)len % (uint64_t)block_len(i) == (uint64_t)0U && (uint64_t)len > (uint64_t)0U)
    {
      ite = block_len(i);
    }
    else
    {
      ite = (uint32_t)((uint64_t)len % (uint64_t)block_len(i));
    }
    uint32_t n_blocks = (len - ite) / block_len(i);
    uint32_t data1_len = n_blocks * block_len(i);
    uint32_t data2_len = len - data1_len;
    uint8_t *data1 = data;
    uint8_t *data2 = data + data1_len;
    Spec_Hash_Definitions_hash_alg a1 = block_state1.fst;
    uint64_t *s2 = block_state1.snd;
    Hacl_Hash_SHA3_update_multi_sha3(a1, s2, data1, data1_len / block_len(a1));
    uint8_t *dst = buf;
    memcpy(dst, data2, data2_len * sizeof (uint8_t));
    *p
    =
      (
        (Hacl_Streaming_Keccak_state){
          .block_state = block_state1,
          .buf = buf,
          .total_len = total_len1 + (uint64_t)len
        }
      );
  }
  else
  {
    uint32_t diff = block_len(i) - sz;
    uint8_t *data1 = data;
    uint8_t *data2 = data + diff;
    Hacl_Streaming_Keccak_state s1 = *p;
    Hacl_Streaming_Keccak_hash_buf block_state10 = s1.block_state;
    uint8_t *buf0 = s1.buf;
    uint64_t total_len10 = s1.total_len;
    uint32_t sz10;
    if (total_len10 % (uint64_t)block_len(i) == (uint64_t)0U && total_len10 > (uint64_t)0U)
    {
      sz10 = block_len(i);
    }
    else
    {
      sz10 = (uint32_t)(total_len10 % (uint64_t)block_len(i));
    }
    uint8_t *buf2 = buf0 + sz10;
    memcpy(buf2, data1, diff * sizeof (uint8_t));
    uint64_t total_len2 = total_len10 + (uint64_t)diff;
    *p
    =
      (
        (Hacl_Streaming_Keccak_state){
          .block_state = block_state10,
          .buf = buf0,
          .total_len = total_len2
        }
      );
    Hacl_Streaming_Keccak_state s10 = *p;
    Hacl_Streaming_Keccak_hash_buf block_state1 = s10.block_state;
    uint8_t *buf = s10.buf;
    uint64_t total_len1 = s10.total_len;
    uint32_t sz1;
    if (total_len1 % (uint64_t)block_len(i) == (uint64_t)0U && total_len1 > (uint64_t)0U)
    {
      sz1 = block_len(i);
    }
    else
    {
      sz1 = (uint32_t)(total_len1 % (uint64_t)block_len(i));
    }
    if (!(sz1 == (uint32_t)0U))
    {
      Spec_Hash_Definitions_hash_alg a1 = block_state1.fst;
      uint64_t *s2 = block_state1.snd;
      Hacl_Hash_SHA3_update_multi_sha3(a1, s2, buf, block_len(i) / block_len(a1));
    }
    uint32_t ite;
    if
    (
      (uint64_t)(len - diff)
      % (uint64_t)block_len(i)
      == (uint64_t)0U
      && (uint64_t)(len - diff) > (uint64_t)0U
    )
    {
      ite = block_len(i);
    }
    else
    {
      ite = (uint32_t)((uint64_t)(len - diff) % (uint64_t)block_len(i));
    }
    uint32_t n_blocks = (len - diff - ite) / block_len(i);
    uint32_t data1_len = n_blocks * block_len(i);
    uint32_t data2_len = len - diff - data1_len;
    uint8_t *data11 = data2;
    uint8_t *data21 = data2 + data1_len;
    Spec_Hash_Definitions_hash_alg a1 = block_state1.fst;
    uint64_t *s2 = block_state1.snd;
    Hacl_Hash_SHA3_update_multi_sha3(a1, s2, data11, data1_len / block_len(a1));
    uint8_t *dst = buf;
    memcpy(dst, data21, data2_len * sizeof (uint8_t));
    *p
    =
      (
        (Hacl_Streaming_Keccak_state){
          .block_state = block_state1,
          .buf = buf,
          .total_len = total_len1 + (uint64_t)(len - diff)
        }
      );
  }
  return Hacl_Streaming_Types_Success;
}

static void
finish_(
  Spec_Hash_Definitions_hash_alg a,
  Hacl_Streaming_Keccak_state *p,
  uint8_t *dst,
  uint32_t l
)
{
  Hacl_Streaming_Keccak_state scrut0 = *p;
  Hacl_Streaming_Keccak_hash_buf block_state = scrut0.block_state;
  uint8_t *buf_ = scrut0.buf;
  uint64_t total_len = scrut0.total_len;
  uint32_t r;
  if (total_len % (uint64_t)block_len(a) == (uint64_t)0U && total_len > (uint64_t)0U)
  {
    r = block_len(a);
  }
  else
  {
    r = (uint32_t)(total_len % (uint64_t)block_len(a));
  }
  uint8_t *buf_1 = buf_;
  uint64_t buf[25U] = { 0U };
  Hacl_Streaming_Keccak_hash_buf tmp_block_state = { .fst = a, .snd = buf };
  hash_buf2 scrut = { .fst = block_state, .snd = tmp_block_state };
  uint64_t *s_dst = scrut.snd.snd;
  uint64_t *s_src = scrut.fst.snd;
  memcpy(s_dst, s_src, (uint32_t)25U * sizeof (uint64_t));
  uint32_t ite;
  if (r % block_len(a) == (uint32_t)0U && r > (uint32_t)0U)
  {
    ite = block_len(a);
  }
  else
  {
    ite = r % block_len(a);
  }
  uint8_t *buf_last = buf_1 + r - ite;
  uint8_t *buf_multi = buf_1;
  Spec_Hash_Definitions_hash_alg a1 = tmp_block_state.fst;
  uint64_t *s0 = tmp_block_state.snd;
  Hacl_Hash_SHA3_update_multi_sha3(a1, s0, buf_multi, (uint32_t)0U / block_len(a1));
  Spec_Hash_Definitions_hash_alg a10 = tmp_block_state.fst;
  uint64_t *s1 = tmp_block_state.snd;
  Hacl_Hash_SHA3_update_last_sha3(a10, s1, buf_last, r);
  Spec_Hash_Definitions_hash_alg a11 = tmp_block_state.fst;
  uint64_t *s = tmp_block_state.snd;
  if (a11 == Spec_Hash_Definitions_Shake128 || a11 == Spec_Hash_Definitions_Shake256)
  {
    Hacl_Impl_SHA3_squeeze(s, block_len(a11), l, dst);
    return;
  }
  Hacl_Impl_SHA3_squeeze(s, block_len(a11), hash_len(a11), dst);
}

Hacl_Streaming_Types_error_code
Hacl_Streaming_Keccak_finish(Hacl_Streaming_Keccak_state *s, uint8_t *dst)
{
  Spec_Hash_Definitions_hash_alg a1 = Hacl_Streaming_Keccak_get_alg(s);
  if (a1 == Spec_Hash_Definitions_Shake128 || a1 == Spec_Hash_Definitions_Shake256)
  {
    return Hacl_Streaming_Types_InvalidAlgorithm;
  }
  finish_(a1, s, dst, hash_len(a1));
  return Hacl_Streaming_Types_Success;
}

Hacl_Streaming_Types_error_code
Hacl_Streaming_Keccak_squeeze(Hacl_Streaming_Keccak_state *s, uint8_t *dst, uint32_t l)
{
  Spec_Hash_Definitions_hash_alg a1 = Hacl_Streaming_Keccak_get_alg(s);
  if (!(a1 == Spec_Hash_Definitions_Shake128 || a1 == Spec_Hash_Definitions_Shake256))
  {
    return Hacl_Streaming_Types_InvalidAlgorithm;
  }
  if (l == (uint32_t)0U)
  {
    return Hacl_Streaming_Types_InvalidLength;
  }
  finish_(a1, s, dst, l);
  return Hacl_Streaming_Types_Success;
}

uint32_t Hacl_Streaming_Keccak_block_len(Hacl_Streaming_Keccak_state *s)
{
  Spec_Hash_Definitions_hash_alg a1 = Hacl_Streaming_Keccak_get_alg(s);
  return block_len(a1);
}

uint32_t Hacl_Streaming_Keccak_hash_len(Hacl_Streaming_Keccak_state *s)
{
  Spec_Hash_Definitions_hash_alg a1 = Hacl_Streaming_Keccak_get_alg(s);
  return hash_len(a1);
}

bool Hacl_Streaming_Keccak_is_shake(Hacl_Streaming_Keccak_state *s)
{
  Spec_Hash_Definitions_hash_alg uu____0 = Hacl_Streaming_Keccak_get_alg(s);
  return uu____0 == Spec_Hash_Definitions_Shake128 || uu____0 == Spec_Hash_Definitions_Shake256;
}

#include "stdio.h"

void
Hacl_SHA3_shake128_hacl(
  uint32_t inputByteLen,
  uint8_t *input,
  uint32_t outputByteLen,
  uint8_t *output
)
{
  Hacl_Impl_SHA3_keccak((uint32_t)1344U,
    (uint32_t)256U,
    inputByteLen,
    input,
    (uint8_t)0x1FU,
    outputByteLen,
    output);
}

void
Hacl_SHA3_shake256_hacl(
  uint32_t inputByteLen,
  uint8_t *input,
  uint32_t outputByteLen,
  uint8_t *output
)
{
  Hacl_Impl_SHA3_keccak((uint32_t)1088U,
    (uint32_t)512U,
    inputByteLen,
    input,
    (uint8_t)0x1FU,
    outputByteLen,
    output);
}

void Hacl_SHA3_sha3_224(uint32_t inputByteLen, uint8_t *input, uint8_t *output)
{
  Hacl_Impl_SHA3_keccak((uint32_t)1152U,
    (uint32_t)448U,
    inputByteLen,
    input,
    (uint8_t)0x06U,
    (uint32_t)28U,
    output);
}

void Hacl_SHA3_sha3_256(uint32_t inputByteLen, uint8_t *input, uint8_t *output)
{
  Hacl_Impl_SHA3_keccak((uint32_t)1088U,
    (uint32_t)512U,
    inputByteLen,
    input,
    (uint8_t)0x06U,
    (uint32_t)32U,
    output);
}

void Hacl_SHA3_sha3_384(uint32_t inputByteLen, uint8_t *input, uint8_t *output)
{
  Hacl_Impl_SHA3_keccak((uint32_t)832U,
    (uint32_t)768U,
    inputByteLen,
    input,
    (uint8_t)0x06U,
    (uint32_t)48U,
    output);
}

void Hacl_SHA3_sha3_512(uint32_t inputByteLen, uint8_t *input, uint8_t *output)
{
  Hacl_Impl_SHA3_keccak((uint32_t)576U,
    (uint32_t)1024U,
    inputByteLen,
    input,
    (uint8_t)0x06U,
    (uint32_t)64U,
    output);
}


// void Hacl_Impl_SHA3_state_permute(uint64_t *s)
// {
//   for (uint32_t i0 = (uint32_t)0U; i0 < (uint32_t)24U; i0++)
//   {
//     uint64_t _C[5U] = { 0U };
//     KRML_MAYBE_FOR5(i,
//       (uint32_t)0U,
//       (uint32_t)5U,
//       (uint32_t)1U,
//       _C[i] =
//         s[i
//         + (uint32_t)0U]
//         ^
//           (s[i
//           + (uint32_t)5U]
//           ^ (s[i + (uint32_t)10U] ^ (s[i + (uint32_t)15U] ^ s[i + (uint32_t)20U]))););
//     KRML_MAYBE_FOR5(i1,
//       (uint32_t)0U,
//       (uint32_t)5U,
//       (uint32_t)1U,
//       uint64_t uu____0 = _C[(i1 + (uint32_t)1U) % (uint32_t)5U];
//       uint64_t
//       _D =
//         _C[(i1 + (uint32_t)4U)
//         % (uint32_t)5U]
//         ^ (uu____0 << (uint32_t)1U | uu____0 >> (uint32_t)63U);
//       KRML_MAYBE_FOR5(i,
//         (uint32_t)0U,
//         (uint32_t)5U,
//         (uint32_t)1U,
//         s[i1 + (uint32_t)5U * i] = s[i1 + (uint32_t)5U * i] ^ _D;););
//     uint64_t x = s[1U];
//     uint64_t current = x;
//     for (uint32_t i = (uint32_t)0U; i < (uint32_t)24U; i++)
//     {
//       uint32_t _Y = keccak_piln[i];
//       uint32_t r = keccak_rotc[i];
//       uint64_t temp = s[_Y];
//       uint64_t uu____1 = current;
//       s[_Y] = uu____1 << r | uu____1 >> ((uint32_t)64U - r);
//       current = temp;
//     }
//     KRML_MAYBE_FOR5(i,
//       (uint32_t)0U,
//       (uint32_t)5U,
//       (uint32_t)1U,
//       uint64_t
//       v0 =
//         s[(uint32_t)0U
//         + (uint32_t)5U * i]
//         ^ (~s[(uint32_t)1U + (uint32_t)5U * i] & s[(uint32_t)2U + (uint32_t)5U * i]);
//       uint64_t
//       v1 =
//         s[(uint32_t)1U
//         + (uint32_t)5U * i]
//         ^ (~s[(uint32_t)2U + (uint32_t)5U * i] & s[(uint32_t)3U + (uint32_t)5U * i]);
//       uint64_t
//       v2 =
//         s[(uint32_t)2U
//         + (uint32_t)5U * i]
//         ^ (~s[(uint32_t)3U + (uint32_t)5U * i] & s[(uint32_t)4U + (uint32_t)5U * i]);
//       uint64_t
//       v3 =
//         s[(uint32_t)3U
//         + (uint32_t)5U * i]
//         ^ (~s[(uint32_t)4U + (uint32_t)5U * i] & s[(uint32_t)0U + (uint32_t)5U * i]);
//       uint64_t
//       v4 =
//         s[(uint32_t)4U
//         + (uint32_t)5U * i]
//         ^ (~s[(uint32_t)0U + (uint32_t)5U * i] & s[(uint32_t)1U + (uint32_t)5U * i]);
//       s[(uint32_t)0U + (uint32_t)5U * i] = v0;
//       s[(uint32_t)1U + (uint32_t)5U * i] = v1;
//       s[(uint32_t)2U + (uint32_t)5U * i] = v2;
//       s[(uint32_t)3U + (uint32_t)5U * i] = v3;
//       s[(uint32_t)4U + (uint32_t)5U * i] = v4;);
//     uint64_t c = keccak_rndc[i0];
//     s[0U] = s[0U] ^ c;
//   }
// }

static inline  void storeState(uint32_t rateInBytes, uint64_t *s, uint8_t *res)
{
  // uint8_t block[200U] = { 0U };
  // for (uint32_t i = (uint32_t)0U; i < (uint32_t)25U; i++)
  // {
  //   uint64_t sj = s[i];
  //   store64_le(block + i * (uint32_t)8U, sj);
  // }
  memcpy(res, s, rateInBytes * sizeof (uint8_t));
}
static inline void
absorb(
  uint64_t *s,
  uint32_t rateInBytes,
  uint32_t inputByteLen,
  uint8_t *input,
  uint8_t delimitedSuffix
)
{
  uint32_t n_blocks = inputByteLen / rateInBytes;
  uint32_t rem = inputByteLen % rateInBytes;
  for (uint32_t i = (uint32_t)0U; i < n_blocks; i++)
  {
    uint8_t *block = input + i * rateInBytes;
    Hacl_Impl_SHA3_absorb_inner(rateInBytes, block, s);
  }
  uint8_t *last = input + n_blocks * rateInBytes;
  uint8_t lastBlock_[200U] = { 0U };
  uint8_t *lastBlock = lastBlock_;
  memcpy(lastBlock, last, rem * sizeof (uint8_t));
  lastBlock[rem] = delimitedSuffix;
  Hacl_Impl_SHA3_loadState(rateInBytes, lastBlock, s);
  if (!((delimitedSuffix & (uint8_t)0x80U) == (uint8_t)0U) && rem == rateInBytes - (uint32_t)1U)
  {
    Hacl_Impl_SHA3_state_permute(s);
  }
  // uint8_t nextBlock_[200U] = { 0U };
  // uint8_t *nextBlock = nextBlock_;
  // nextBlock[rateInBytes - (uint32_t)1U] = (uint8_t)0x80U;
  // Hacl_Impl_SHA3_loadState(rateInBytes, nextBlock, s);
  Hacl_Impl_SHA3_state_permute(s);
}

void
Hacl_Impl_SHA3_squeeze(
  uint64_t *s,
  uint32_t rateInBytes,
  uint32_t outputByteLen,
  uint8_t *output
)
{
  // uint32_t outBlocks = outputByteLen / rateInBytes;
  // uint32_t remOut = outputByteLen % rateInBytes;
  // uint8_t *last = output + outputByteLen - remOut;
  // uint8_t *blocks = output;
  // for (uint32_t i = (uint32_t)0U; i < outBlocks; i++)
  // {
  //   storeState(rateInBytes, s, blocks + i * rateInBytes);
  //   Hacl_Impl_SHA3_state_permute(s);
  // }
  // storeState(remOut, s, last);

  // Accessing |ctx->state| as a |uint8_t*| is allowed by strict aliasing
  // because we require |uint8_t| to be a character type.
  const uint8_t *state_bytes = (const uint8_t *)s;  
  size_t offset = 0;
  while (outputByteLen) {
    size_t remaining = rateInBytes - offset;
    size_t todo = outputByteLen;
    if (todo > remaining) {
      todo = remaining;
    }
    memcpy(output, &state_bytes[offset], todo);
    output += todo;
    outputByteLen -= todo;
    offset += todo;
    if (offset == rateInBytes) {
      Hacl_Impl_SHA3_state_permute(s);
      offset = 0;
    }
  }
}

void
Hacl_Impl_SHA3_keccak(
  uint32_t rate,
  uint32_t capacity,
  uint32_t inputByteLen,
  uint8_t *input,
  uint8_t delimitedSuffix,
  uint32_t outputByteLen,
  uint8_t *output
)
{
  uint32_t rateInBytes = rate / (uint32_t)8U;
  uint64_t s[25U] = { 0U };
  absorb(s, rateInBytes, inputByteLen, input, delimitedSuffix);
  Hacl_Impl_SHA3_squeeze_(s, rateInBytes, outputByteLen, output);
}

