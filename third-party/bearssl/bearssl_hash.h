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

#ifndef BR_BEARSSL_HASH_H__
#define BR_BEARSSL_HASH_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Type for a GHASH implementation.
 *
 * GHASH is a sort of keyed hash meant to be used to implement GCM in
 * combination with a block cipher (with 16-byte blocks).
 *
 * The `y` array has length 16 bytes and is used for input and output; in
 * a complete GHASH run, it starts with an all-zero value. `h` is a 16-byte
 * value that serves as key (it is derived from the encryption key in GCM,
 * using the block cipher). The data length (`len`) is expressed in bytes.
 * The `y` array is updated.
 *
 * If the data length is not a multiple of 16, then the data is implicitly
 * padded with zeros up to the next multiple of 16. Thus, when using GHASH
 * in GCM, this method may be called twice, for the associated data and
 * for the ciphertext, respectively; the zero-padding implements exactly
 * the GCM rules.
 *
 * \param y      the array to update.
 * \param h      the GHASH key.
 * \param data   the input data (may be `NULL` if `len` is zero).
 * \param len    the input data length (in bytes).
 */
typedef void (*br_ghash)(void *y, const void *h, const void *data, size_t len);

/**
 * \brief GHASH implementation using multiplications (64-bit).
 *
 * This implementation uses multiplications of 64-bit values, with a
 * 64-bit result. It is constant-time (if multiplications are
 * constant-time). It is substantially faster than `br_ghash_ctmul()`
 * and `br_ghash_ctmul32()` on most 64-bit architectures.
 *
 * \param y      the array to update.
 * \param h      the GHASH key.
 * \param data   the input data (may be `NULL` if `len` is zero).
 * \param len    the input data length (in bytes).
 */
void br_ghash_ctmul64(void *y, const void *h, const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
