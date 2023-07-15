/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef INNER_H__
#define INNER_H__

#include <string.h>

static inline void
br_enc32le(void *dst, uint32_t x)
{
#if BR_LE_UNALIGNED
	((br_union_u32 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)x;
	buf[1] = (unsigned char)(x >> 8);
	buf[2] = (unsigned char)(x >> 16);
	buf[3] = (unsigned char)(x >> 24);
#endif
}

static inline void
br_enc32be(void *dst, uint32_t x)
{
#if BR_BE_UNALIGNED
	((br_union_u32 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)(x >> 24);
	buf[1] = (unsigned char)(x >> 16);
	buf[2] = (unsigned char)(x >> 8);
	buf[3] = (unsigned char)x;
#endif
}

static inline uint32_t
br_dec32le(const void *src)
{
#if BR_LE_UNALIGNED
	return ((const br_union_u32 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return (uint32_t)buf[0]
		| ((uint32_t)buf[1] << 8)
		| ((uint32_t)buf[2] << 16)
		| ((uint32_t)buf[3] << 24);
#endif
}

static inline uint32_t
br_dec32be(const void *src)
{
#if BR_BE_UNALIGNED
	return ((const br_union_u32 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return ((uint32_t)buf[0] << 24)
		| ((uint32_t)buf[1] << 16)
		| ((uint32_t)buf[2] << 8)
		| (uint32_t)buf[3];
#endif
}

static inline void
br_enc64be(void *dst, uint64_t x)
{
#if BR_BE_UNALIGNED
	((br_union_u64 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	br_enc32be(buf, (uint32_t)(x >> 32));
	br_enc32be(buf + 4, (uint32_t)x);
#endif
}

static inline uint64_t
br_dec64be(const void *src)
{
#if BR_BE_UNALIGNED
	return ((const br_union_u64 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return ((uint64_t)br_dec32be(buf) << 32)
		| (uint64_t)br_dec32be(buf + 4);
#endif
}

/*
 * Range decoding and encoding (for several successive values).
 */
void br_range_dec32le(uint32_t *v, size_t num, const void *src);
void br_range_enc32le(void *dst, const uint32_t *v, size_t num);

/*
 * Byte-swap a 32-bit integer.
 */
static inline uint32_t
br_swap32(uint32_t x)
{
	x = ((x & (uint32_t)0x00FF00FF) << 8)
		| ((x >> 8) & (uint32_t)0x00FF00FF);
	return (x << 16) | (x >> 16);
}

/*
 * Returns 1 if x == 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
EQ0(int32_t x)
{
	uint32_t q;

	q = (uint32_t)x;
	return ~(q | -q) >> 31;
}

/*
 * Perform bytewise orthogonalization of eight 64-bit words. Bytes
 * of q0..q7 are spread over all words: for a byte x that occurs
 * at rank i in q[j] (byte x uses bits 8*i to 8*i+7 in q[j]), the bit
 * of rank k in x (0 <= k <= 7) goes to q[k] at rank 8*i+j.
 *
 * This operation is an involution.
 */
void br_aes_ct64_ortho(uint64_t *q);

/*
 * Interleave bytes for an AES input block. If input bytes are
 * denoted 0123456789ABCDEF, and have been decoded with little-endian
 * convention (w[0] contains 0123, with '3' being most significant;
 * w[1] contains 4567, and so on), then output word q0 will be
 * set to 08192A3B (again little-endian convention) and q1 will
 * be set to 4C5D6E7F.
 */
void br_aes_ct64_interleave_in(uint64_t *q0, uint64_t *q1, const uint32_t *w);

/*
 * Perform the opposite of br_aes_ct64_interleave_in().
 */
void br_aes_ct64_interleave_out(uint32_t *w, uint64_t q0, uint64_t q1);

/*
 * The AES S-box, as a bitsliced constant-time version. The input array
 * consists in eight 64-bit words; 64 S-box instances are computed in
 * parallel. Bits 0 to 7 of each S-box input (bit 0 is least significant)
 * are spread over the words 0 to 7, at the same rank.
 */
void br_aes_ct64_bitslice_Sbox(uint64_t *q);

/*
 * Compute AES encryption on bitsliced data. Since input is stored on
 * eight 64-bit words, four block encryptions are actually performed
 * in parallel.
 */
void br_aes_ct64_bitslice_encrypt(unsigned num_rounds,
	const uint64_t *skey, uint64_t *q);

/*
 * AES key schedule, constant-time version. skey[] is filled with n+1
 * 128-bit subkeys, where n is the number of rounds (10 to 14, depending
 * on key size). The number of rounds is returned. If the key size is
 * invalid (not 16, 24 or 32), then 0 is returned.
 */
unsigned br_aes_ct64_keysched(uint64_t *comp_skey,
	const void *key, size_t key_len);

/*
 * Expand AES subkeys as produced by br_aes_ct64_keysched(), into
 * a larger array suitable for br_aes_ct64_bitslice_encrypt() and
 * br_aes_ct64_bitslice_decrypt().
 */
void br_aes_ct64_skey_expand(uint64_t *skey,
	unsigned num_rounds, const uint64_t *comp_skey);

/* ==================================================================== */

#endif
