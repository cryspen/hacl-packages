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


#include "Hacl_AES_128_GCM_CT64.h"

#include "internal/Hacl_AES_128_CTR32_BitSlice.h"

uint32_t Hacl_AES_128_GCM_CT64_aes_gcm_ctx_len = (uint32_t)116U;

void Hacl_AES_128_GCM_CT64_aes128_gcm_init(uint64_t *ctx, uint8_t *key)
{
  uint8_t gcm_key[16U] = { 0U };
  uint8_t nonce0[12U] = { 0U };
  uint64_t *aes_ctx = ctx;
  uint64_t *gcm_ctx = ctx + (uint32_t)96U;
  Hacl_AES_128_CTR32_BitSlice_aes128_init(aes_ctx, key, nonce0);
  Hacl_AES_128_CTR32_BitSlice_aes128_key_block(gcm_key, aes_ctx, (uint32_t)0U);
  Hacl_Gf128_CT64_gcm_init(gcm_ctx, gcm_key);
}

void
Hacl_AES_128_GCM_CT64_aes128_gcm_encrypt(
  uint64_t *ctx,
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint32_t aad_len,
  uint8_t *aad,
  uint32_t iv_len,
  uint8_t *iv
)
{
  uint8_t tmp[16U] = { 0U };
  uint8_t *cip = out;
  uint64_t *aes_ctx = ctx;
  uint64_t *gcm_ctx = ctx + (uint32_t)96U;
  uint64_t *tag_mix = ctx + (uint32_t)114U;
  uint32_t ctr;
  uint8_t tag_mix10[16U] = { 0U };
  uint8_t gcm_key[16U] = { 0U };
  uint8_t tag_iv[16U] = { 0U };
  uint8_t size_iv[16U] = { 0U };
  uint8_t tag_mix1[16U] = { 0U };
  if (iv_len == (uint32_t)12U)
  {
    uint64_t *aes_ctx1 = ctx;
    Hacl_AES_128_CTR32_BitSlice_aes128_set_nonce(aes_ctx1, iv);
    Hacl_AES_128_CTR32_BitSlice_aes128_key_block(tag_mix10, aes_ctx1, (uint32_t)1U);
    uint64_t u = load64_le(tag_mix10);
    ctx[114U] = u;
    uint64_t u0 = load64_le(tag_mix10 + (uint32_t)8U);
    ctx[115U] = u0;
    ctr = (uint32_t)2U;
  }
  else
  {
    uint64_t *aes_ctx1 = ctx;
    uint64_t *gcm_ctx1 = ctx + (uint32_t)96U;
    store64_be(gcm_key + (uint32_t)8U, gcm_ctx1[8U]);
    store64_be(gcm_key, gcm_ctx1[9U]);
    Hacl_Gf128_CT64_ghash(tag_iv, iv_len, iv, gcm_key);
    store64_be(size_iv + (uint32_t)8U, (uint64_t)(iv_len * (uint32_t)8U));
    KRML_MAYBE_FOR16(i,
      (uint32_t)0U,
      (uint32_t)16U,
      (uint32_t)1U,
      size_iv[i] = tag_iv[i] ^ size_iv[i];);
    Hacl_Gf128_CT64_ghash(tag_iv, (uint32_t)16U, size_iv, gcm_key);
    Hacl_AES_128_CTR32_BitSlice_aes128_set_nonce(aes_ctx1, tag_iv);
    uint32_t u0 = load32_be(tag_iv + (uint32_t)12U);
    uint32_t ctr0 = u0;
    Hacl_AES_128_CTR32_BitSlice_aes128_key_block(tag_mix1, aes_ctx1, ctr0);
    uint64_t u = load64_le(tag_mix1);
    ctx[114U] = u;
    uint64_t u1 = load64_le(tag_mix1 + (uint32_t)8U);
    ctx[115U] = u1;
    ctr = ctr0 + (uint32_t)1U;
  }
  Hacl_Impl_AES_Generic_aes128_ctr_bitslice(len, cip, text, aes_ctx, ctr);
  gcm_ctx[0U] = (uint64_t)0U;
  gcm_ctx[1U] = (uint64_t)0U;
  Hacl_Gf128_CT64_gcm_update_blocks_padded(gcm_ctx, aad_len, aad);
  Hacl_Gf128_CT64_gcm_update_blocks_padded(gcm_ctx, len, cip);
  store64_be(tmp, (uint64_t)(aad_len * (uint32_t)8U));
  store64_be(tmp + (uint32_t)8U, (uint64_t)(len * (uint32_t)8U));
  Hacl_Gf128_CT64_gcm_update_blocks(gcm_ctx, (uint32_t)16U, tmp);
  Hacl_Gf128_CT64_gcm_emit(tmp, gcm_ctx);
  uint64_t u0 = load64_le(tmp);
  uint64_t tmp0 = u0;
  uint64_t u = load64_le(tmp + (uint32_t)8U);
  uint64_t tmp1 = u;
  uint64_t tmp01 = tmp0 ^ tag_mix[0U];
  uint64_t tmp11 = tmp1 ^ tag_mix[1U];
  store64_le(out + len, tmp01);
  store64_le(out + len + (uint32_t)8U, tmp11);
}

bool
Hacl_AES_128_GCM_CT64_aes128_gcm_decrypt(
  uint64_t *ctx,
  uint32_t len,
  uint8_t *out,
  uint8_t *cipher,
  uint32_t aad_len,
  uint8_t *aad,
  uint32_t iv_len,
  uint8_t *iv
)
{
  uint8_t scratch[18U] = { 0U };
  uint8_t *text = scratch;
  uint8_t *result = scratch + (uint32_t)17U;
  uint8_t *ciphertext = cipher;
  uint8_t *tag = cipher + len;
  uint32_t ctr;
  uint8_t tag_mix0[16U] = { 0U };
  uint8_t gcm_key[16U] = { 0U };
  uint8_t tag_iv[16U] = { 0U };
  uint8_t size_iv[16U] = { 0U };
  uint8_t tag_mix1[16U] = { 0U };
  if (iv_len == (uint32_t)12U)
  {
    uint64_t *aes_ctx = ctx;
    Hacl_AES_128_CTR32_BitSlice_aes128_set_nonce(aes_ctx, iv);
    Hacl_AES_128_CTR32_BitSlice_aes128_key_block(tag_mix0, aes_ctx, (uint32_t)1U);
    uint64_t u = load64_le(tag_mix0);
    ctx[114U] = u;
    uint64_t u0 = load64_le(tag_mix0 + (uint32_t)8U);
    ctx[115U] = u0;
    ctr = (uint32_t)2U;
  }
  else
  {
    uint64_t *aes_ctx = ctx;
    uint64_t *gcm_ctx = ctx + (uint32_t)96U;
    store64_be(gcm_key + (uint32_t)8U, gcm_ctx[8U]);
    store64_be(gcm_key, gcm_ctx[9U]);
    Hacl_Gf128_CT64_ghash(tag_iv, iv_len, iv, gcm_key);
    store64_be(size_iv + (uint32_t)8U, (uint64_t)(iv_len * (uint32_t)8U));
    KRML_MAYBE_FOR16(i,
      (uint32_t)0U,
      (uint32_t)16U,
      (uint32_t)1U,
      size_iv[i] = tag_iv[i] ^ size_iv[i];);
    Hacl_Gf128_CT64_ghash(tag_iv, (uint32_t)16U, size_iv, gcm_key);
    Hacl_AES_128_CTR32_BitSlice_aes128_set_nonce(aes_ctx, tag_iv);
    uint32_t u0 = load32_be(tag_iv + (uint32_t)12U);
    uint32_t ctr0 = u0;
    Hacl_AES_128_CTR32_BitSlice_aes128_key_block(tag_mix1, aes_ctx, ctr0);
    uint64_t u = load64_le(tag_mix1);
    ctx[114U] = u;
    uint64_t u1 = load64_le(tag_mix1 + (uint32_t)8U);
    ctx[115U] = u1;
    ctr = ctr0 + (uint32_t)1U;
  }
  uint64_t *aes_ctx = ctx;
  uint64_t *gcm_ctx = ctx + (uint32_t)96U;
  uint64_t *tag_mix = ctx + (uint32_t)114U;
  gcm_ctx[0U] = (uint64_t)0U;
  gcm_ctx[1U] = (uint64_t)0U;
  Hacl_Gf128_CT64_gcm_update_blocks_padded(gcm_ctx, aad_len, aad);
  Hacl_Gf128_CT64_gcm_update_blocks_padded(gcm_ctx, len, ciphertext);
  store64_be(text, (uint64_t)(aad_len * (uint32_t)8U));
  store64_be(text + (uint32_t)8U, (uint64_t)(len * (uint32_t)8U));
  Hacl_Gf128_CT64_gcm_update_blocks(gcm_ctx, (uint32_t)16U, text);
  Hacl_Gf128_CT64_gcm_emit(text, gcm_ctx);
  uint64_t u0 = load64_le(text);
  uint64_t text0 = u0;
  uint64_t u = load64_le(text + (uint32_t)8U);
  uint64_t text1 = u;
  uint64_t text01 = text0 ^ tag_mix[0U];
  uint64_t text11 = text1 ^ tag_mix[1U];
  store64_le(text, text01);
  store64_le(text + (uint32_t)8U, text11);
  KRML_MAYBE_FOR16(i,
    (uint32_t)0U,
    (uint32_t)16U,
    (uint32_t)1U,
    result[0U] = result[0U] | (text[i] ^ tag[i]););
  uint8_t res8 = result[0U];
  if (res8 == (uint8_t)0U)
  {
    Hacl_Impl_AES_Generic_aes128_ctr_bitslice(len, out, ciphertext, aes_ctx, ctr);
    return true;
  }
  return false;
}

