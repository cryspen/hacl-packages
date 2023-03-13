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


#ifndef __Hacl_Hash_Blake2b_32_H
#define __Hacl_Hash_Blake2b_32_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"

#include "Lib_Memzero0.h"
#include "Hacl_Krmllib.h"

void Hacl_Hash_Blake2b_32_init(uint64_t *hash, uint32_t kk, uint32_t nn);

void
Hacl_Hash_Blake2b_32_update_key(
  uint64_t *wv,
  uint64_t *hash,
  uint32_t kk,
  uint8_t *k,
  uint32_t ll
);

void
Hacl_Hash_Blake2b_32_update_multi(
  uint32_t len,
  uint64_t *wv,
  uint64_t *hash,
  FStar_UInt128_uint128 prev,
  uint8_t *blocks,
  uint32_t nb
);

void
Hacl_Hash_Blake2b_32_update_last(
  uint32_t len,
  uint64_t *wv,
  uint64_t *hash,
  FStar_UInt128_uint128 prev,
  uint32_t rem,
  uint8_t *d
);

void Hacl_Hash_Blake2b_32_finish(uint32_t nn, uint8_t *output, uint64_t *hash);

/**
Write the BLAKE2b digest of message `input` using key `key` into `output`.

@param output Pointer to `output_len` bytes of memory where the digest is written to.
@param output_len Length of the to-be-generated digest with 1 <= `output_len` <= 64.
@param input Pointer to `input_len` bytes of memory where the input message is read from.
@param input_len Length of the input message.
@param key Pointer to `key_len` bytes of memory where the key is read from.
@param key_len Length of the key. Can be 0.
*/
void
Hacl_Hash_Blake2b_32_hash_with_key(
  uint8_t *output,
  uint32_t output_len,
  uint8_t *input,
  uint32_t input_len,
  uint8_t *key,
  uint32_t key_len
);

uint64_t *Hacl_Hash_Blake2b_32_malloc_with_key(void);

typedef struct Hacl_Hash_Blake2b_32_block_state_t_s
{
  uint64_t *fst;
  uint64_t *snd;
}
Hacl_Hash_Blake2b_32_block_state_t;

typedef struct Hacl_Hash_Blake2b_32_state_t_s
{
  Hacl_Hash_Blake2b_32_block_state_t block_state;
  uint8_t *buf;
  uint64_t total_len;
}
Hacl_Hash_Blake2b_32_state_t;

/**
  State allocation function when there is no key
*/
Hacl_Hash_Blake2b_32_state_t *Hacl_Hash_Blake2b_32_malloc(void);

/**
  Re-initialization function when there is no key
*/
void Hacl_Hash_Blake2b_32_reset(Hacl_Hash_Blake2b_32_state_t *state);

/**
  Update function when there is no key; 0 = success, 1 = max length exceeded
*/
uint32_t
Hacl_Hash_Blake2b_32_update(
  Hacl_Hash_Blake2b_32_state_t *state,
  uint8_t *chunk,
  uint32_t chunk_len
);

/**
  Finish function when there is no key
*/
void Hacl_Hash_Blake2b_32_digest(Hacl_Hash_Blake2b_32_state_t *state, uint8_t *output);

/**
  Free state function when there is no key
*/
void Hacl_Hash_Blake2b_32_free(Hacl_Hash_Blake2b_32_state_t *state);

#if defined(__cplusplus)
}
#endif

#define __Hacl_Hash_Blake2b_32_H_DEFINED
#endif