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

#ifndef BR_BEARSSL_BLOCK_H__
#define BR_BEARSSL_BLOCK_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Class type for CTR encryption/decryption implementations.
 *
 * A `br_block_ctr_class` instance points to the functions implementing
 * a specific block cipher, when used in CTR mode for encrypting or
 * decrypting data.
 */
typedef struct br_block_ctr_class_ br_block_ctr_class;
struct br_block_ctr_class_ {
	/**
	 * \brief Size (in bytes) of the context structure appropriate
	 * for containing subkeys.
	 */
	size_t context_size;

	/**
	 * \brief Size of individual blocks (in bytes).
	 */
	unsigned block_size;

	/**
	 * \brief Base-2 logarithm of the size of individual blocks,
	 * expressed in bytes.
	 */
	unsigned log_block_size;

	/**
	 * \brief Initialisation function.
	 *
	 * This function sets the `vtable` field in the context structure.
	 * The key length MUST be one of the key lengths supported by
	 * the implementation.
	 *
	 * \param ctx       context structure to initialise.
	 * \param key       secret key.
	 * \param key_len   key length (in bytes).
	 */
	void (*init)(const br_block_ctr_class **ctx,
		const void *key, size_t key_len);

	/**
	 * \brief Run the CTR encryption or decryption.
	 *
	 * The `iv` parameter points to the IV for this run; its
	 * length is exactly 4 bytes less than the block size (e.g.
	 * 12 bytes for AES/CTR). The IV is combined with a 32-bit
	 * block counter to produce the block value which is processed
	 * with the block cipher.
	 *
	 * The data to encrypt or decrypt is updated "in place". Its
	 * length (`len` bytes) is not required to be a multiple of
	 * the block size; if the final block is partial, then the
	 * corresponding key stream bits are dropped.
	 *
	 * The resulting counter value is returned.
	 *
	 * \param ctx    context structure (already initialised).
	 * \param iv     IV for CTR encryption/decryption.
	 * \param cc     initial value for the block counter.
	 * \param data   data to encrypt or decrypt.
	 * \param len    data length (in bytes).
	 * \return  the new block counter value.
	 */
	uint32_t (*run)(const br_block_ctr_class *const *ctx,
		const void *iv, uint32_t cc, void *data, size_t len);
};

/** \brief AES block size (16 bytes). */
#define br_aes_ct64_BLOCK_SIZE   16

/**
 * \brief Context for AES subkeys (`aes_ct64` implementation, CTR encryption
 * and decryption).
 *
 * First field is a pointer to the vtable; it is set by the initialisation
 * function. Other fields are not supposed to be accessed by user code.
 */
typedef struct {
	/** \brief Pointer to vtable for this context. */
	const br_block_ctr_class *vtable;
	uint64_t skey[30];
	unsigned num_rounds;
} br_aes_ct64_ctr_keys;

/**
 * \brief Class instance for AES CTR encryption and decryption
 * (`aes_ct64` implementation).
 */
extern const br_block_ctr_class br_aes_ct64_ctr_vtable;

/*
 * 64-bit constant-time AES implementation. It is similar to 'aes_ct'
 * but uses 64-bit registers, making it about twice faster than 'aes_ct'
 * on 64-bit platforms, while remaining constant-time and with a similar
 * code size. (The doubling in performance is only for CBC decryption
 * and CTR mode; CBC encryption is non-parallel and cannot benefit from
 * the larger registers.)
 */

/**
 * \brief Context initialisation (key schedule) for AES CTR encryption
 * and decryption (`aes_ct64` implementation).
 *
 * \param ctx   context to initialise.
 * \param key   secret key.
 * \param len   secret key length (in bytes).
 */
void br_aes_ct64_ctr_init(br_aes_ct64_ctr_keys *ctx,
	const void *key, size_t len);

/**
 * \brief CTR encryption and decryption with AES (`aes_ct64` implementation).
 *
 * \param ctx    context (already initialised).
 * \param iv     IV (constant, 12 bytes).
 * \param cc     initial block counter value.
 * \param data   data to decrypt (updated).
 * \param len    data length (in bytes).
 * \return  new block counter value.
 */
uint32_t br_aes_ct64_ctr_run(const br_aes_ct64_ctr_keys *ctx,
	const void *iv, uint32_t cc, void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
