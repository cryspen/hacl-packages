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


#ifndef __Hacl_AES_256_CTR32_NI_H
#define __Hacl_AES_256_CTR32_NI_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"

#include "libintvector.h"

typedef Lib_IntVector_Intrinsics_vec128 *Hacl_AES_256_CTR32_NI_aes_ctx;

typedef uint8_t *Hacl_AES_256_CTR32_NI_skey;

void
Hacl_AES_256_CTR32_NI_aes256_init(
  Lib_IntVector_Intrinsics_vec128 *ctx,
  uint8_t *key,
  uint8_t *nonce
);

void
Hacl_AES_256_CTR32_NI_aes256_set_nonce(Lib_IntVector_Intrinsics_vec128 *ctx, uint8_t *nonce);

void
Hacl_AES_256_CTR32_NI_aes256_key_block(
  uint8_t *kb,
  Lib_IntVector_Intrinsics_vec128 *ctx,
  uint32_t counter
);

void
Hacl_AES_256_CTR32_NI_aes256_ctr(
  uint32_t len,
  uint8_t *out,
  uint8_t *inp,
  Lib_IntVector_Intrinsics_vec128 *ctx,
  uint32_t c
);

void
Hacl_AES_256_CTR32_NI_aes256_ctr_encrypt(
  uint32_t len,
  uint8_t *out,
  uint8_t *inp,
  uint8_t *k,
  uint8_t *n,
  uint32_t c
);

void
Hacl_AES_256_CTR32_NI_aes256_ctr_decrypt(
  uint32_t len,
  uint8_t *out,
  uint8_t *inp,
  uint8_t *k,
  uint8_t *n,
  uint32_t c
);

#if defined(__cplusplus)
}
#endif

#define __Hacl_AES_256_CTR32_NI_H_DEFINED
#endif