/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "Hacl_RSA.h"

#include "util.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl_rsa.h"


void
HACL_RSA_enc(benchmark::State& state)
{
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSA_new_rsa_load_skey(modBits, eBits, dBits, mod, e, d);
  uint64_t* pkey = Hacl_RSA_new_rsa_load_pkey(modBits, eBits, mod, e);
  uint8_t msg[256] = {0};
  uint8_t cipher[256] = {0};

  for (auto _ : state) {
    Hacl_RSA_rsa_enc(modBits,
                     eBits,
                     pkey,
                     msg,
                     cipher);
  }

  free(skey);
  free(pkey);
  free(mod);
  free(d);
  free(e);
}

BENCHMARK(HACL_RSA_enc)->Setup(DoSetup);


/*
 * For do_encrypt(), load an RSA public key from pub_key_der[].
 * For do_decrypt(), load an RSA private key from priv_key_der[].
 */
static EVP_PKEY *get_pub_key(OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    int selection;
    const unsigned char *data;
    size_t data_len;

    selection = EVP_PKEY_PUBLIC_KEY;
    data = pub_key_der;
    data_len = sizeof(pub_key_der);

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "RSA",
                                         selection, libctx, propq);
    (void)OSSL_DECODER_from_data(dctx, &data, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}


/* Set optional parameters for RSA OAEP Padding */
static void set_optional_params(OSSL_PARAM *p, const char *propq)
{
    static unsigned char label[] = "label";

    /* "pkcs1" is used by default if the padding mode is not set */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                            OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
    /* No oaep_label is used if this is not set */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                             label, sizeof(label));
    /* "SHA1" is used if this is not set */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                            "SHA256", 0);
    /*
     * If a non default property query needs to be specified when fetching the
     * OAEP digest then it needs to be specified here.
     */
    if (propq != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
                                                (char *)propq, 0);

    /*
     * OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST and
     * OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS can also be optionally added
     * here if the MGF1 digest differs from the OAEP digest.
     */

    *p = OSSL_PARAM_construct_end();
}

void
OPENSSL_RSA_enc(benchmark::State& state)
{
    int ret = 0;
    size_t buf_len = 0;
    unsigned char *buf = NULL;
    const char *propq = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pub_key = NULL;
    OSSL_PARAM params[5];
    OSSL_LIB_CTX *libctx = NULL;
    size_t msg_len = sizeof(msg) - 1;
    size_t cipherlen = 512;


    /* Get public key */
    pub_key = get_pub_key(libctx, propq);
    if (pub_key == NULL) {
        fprintf(stderr, "Get public key failed.\n");
        goto cleanup;
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub_key, propq);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
        goto cleanup;
    }
    set_optional_params(params, propq);
    /* If no optional parameters are required then NULL can be passed */
	
    for (auto _ : state) {
    if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt_init_ex() failed.\n");
        goto cleanup;
    }
   /* Calculate the size required to hold the encrypted data */
    if (EVP_PKEY_encrypt(ctx, NULL, &buf_len, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt() failed.\n");
        goto cleanup;
    }
    buf = (unsigned char*) OPENSSL_zalloc(buf_len);
    if (buf  == NULL) {
        fprintf(stderr, "Malloc failed.\n");
        goto cleanup;
    }
    if (EVP_PKEY_encrypt(ctx, buf, &buf_len, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt() failed.\n");
        goto cleanup;
    }
    }

    ret = 1;

cleanup:
    OPENSSL_free(buf);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_CTX_free(ctx);
}

//BENCHMARK(OPENSSL_RSA_enc)->Setup(DoSetup);


void
HACL_RSA_dec(benchmark::State& state)
{
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSA_new_rsa_load_skey(modBits, eBits, dBits, mod, e, d);
  uint64_t* pkey = Hacl_RSA_new_rsa_load_pkey(modBits, eBits, mod, e);
  uint8_t msg[256] = {0};
  uint8_t cipher[256] = {0};

  Hacl_RSA_rsa_enc(modBits,
                   eBits,
                   pkey,
                   msg,
                   cipher);
  
  for (auto _ : state) {
    Hacl_RSA_rsa_dec(modBits,
                     eBits,
                     dBits,
                     skey,
                     cipher,
                     msg);
  }

  free(pkey);
  free(skey);
  free(mod);
  free(d);
  free(e);
}

//BENCHMARK(HACL_RSA_dec)->Setup(DoSetup);

static EVP_PKEY *get_priv_key(OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    int selection;
    const unsigned char *data;
    size_t data_len;

    selection = EVP_PKEY_KEYPAIR;
    data = priv_key_der;
    data_len = sizeof(priv_key_der);

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "RSA",
                                         selection, libctx, propq);
    (void)OSSL_DECODER_from_data(dctx, &data, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

void
OPENSSL_RSA_dec(benchmark::State& state)
{
    int ret = 0;
    size_t ctxt_len = 0;
    unsigned char *ctxt = NULL;
    size_t ptxt_len = 0;
    unsigned char *ptxt = NULL;
    const char *propq = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *priv_key = NULL;
    OSSL_PARAM params[5];
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pub_key = NULL;

    size_t msg_len = sizeof(msg) - 1;
    size_t cipherlen = 512;

    /* Get public key */
    pub_key = get_pub_key(libctx, propq);
    if (pub_key == NULL) {
        fprintf(stderr, "Get public key failed.\n");
        goto cleanup;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub_key, propq);
    if (pctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
        goto cleanup;
    }
    set_optional_params(params, propq);
    /* If no optional parameters are required then NULL can be passed */
    if (EVP_PKEY_encrypt_init_ex(pctx, params) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt_init_ex() failed.\n");
        goto cleanup;
    }
    /* Calculate the size required to hold the encrypted data */
    if (EVP_PKEY_encrypt(pctx, NULL, &ctxt_len, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt() failed.\n");
        goto cleanup;
    }
    ctxt = (unsigned char*) OPENSSL_zalloc(ctxt_len);
    if (ctxt  == NULL) {
        fprintf(stderr, "Malloc failed.\n");
        goto cleanup;
    }
    if (EVP_PKEY_encrypt(pctx, ctxt, &ctxt_len, msg, msg_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt() failed.\n");
        goto cleanup;
    }

    /* Get private key */
    priv_key = get_priv_key(libctx, propq);
    if (priv_key == NULL) {
        fprintf(stderr, "Get private key failed.\n");
        goto cleanup;
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv_key, propq);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
        goto cleanup;
    }
    set_optional_params(params, propq);
    /* If no optional parameters are required then NULL can be passed */
 
    for (auto _ : state) {
    if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt_init_ex() failed.\n");
        goto cleanup;
    }

   /* Calculate the size required to hold the decrypted data */
    if (EVP_PKEY_decrypt(ctx, NULL, &ptxt_len, ctxt, ctxt_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt() failed 1.\n");
        goto cleanup;
    }
    ptxt = (unsigned char*) OPENSSL_zalloc(ptxt_len);
    if (ptxt  == NULL) {
        fprintf(stderr, "Malloc failed.\n");
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(ctx, ptxt, &ptxt_len, ctxt, ctxt_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt() failed 2.\n");
        goto cleanup;
    }
    }

    ret = 1;

cleanup:
    OPENSSL_free(ptxt);
    OPENSSL_free(ctxt);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_CTX_free(pctx);
}

//BENCHMARK(OPENSSL_RSA_dec)->Setup(DoSetup);

BENCHMARK_MAIN();
