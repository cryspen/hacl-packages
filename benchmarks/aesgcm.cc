/*
 *    Copyright 2023 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "util.h"

#include "krml/internal/target.h"
#ifdef HACL_CAN_COMPILE_AESNI_PCLMUL
#include "Hacl_AES_128_GCM_NI.h"
#endif
#include "Hacl_AES_128_GCM_CT64.h"
#include "EverCrypt_AEAD.h"
#include "../third-party/bearssl/bearssl_block.h"
#include "../third-party/bearssl/bearssl_hash.h"
#include "../third-party/bearssl/bearssl_aead.h"

static bytes key(16, 7);
static bytes nonce(12, 9);
static bytes mac(16, 0);

#ifdef HACL_CAN_COMPILE_AESNI_PCLMUL
static void
HACL_AES_128_GCM_NI_encrypt(benchmark::State& state)
{
  bytes plaintext(state.range(0), 0x37);
  bytes ciphertext(state.range(0) + 16, 0);
  
  for (auto _ : state) {
    Lib_IntVector_Intrinsics_vec128 *ctx = (Lib_IntVector_Intrinsics_vec128 *)KRML_HOST_CALLOC((uint32_t)288U, sizeof (uint8_t));
    Hacl_AES_128_GCM_NI_aes128_gcm_init(ctx, key.data());
    Hacl_AES_128_GCM_NI_aes128_gcm_encrypt(ctx, plaintext.size(), ciphertext.data(), plaintext.data(), 0, NULL, nonce.size(), nonce.data());
    KRML_HOST_FREE(ctx);
  }
}

BENCHMARK(HACL_AES_128_GCM_NI_encrypt)->Setup(DoSetup)->Apply(Range);

static void
HACL_AES_128_GCM_NI_aad(benchmark::State& state)
{
  bytes aad(state.range(0), 0x37);
  
  for (auto _ : state) {
    Lib_IntVector_Intrinsics_vec128 *ctx = (Lib_IntVector_Intrinsics_vec128 *)KRML_HOST_CALLOC((uint32_t)288U, sizeof (uint8_t));
    Hacl_AES_128_GCM_NI_aes128_gcm_init(ctx, key.data());
    Hacl_AES_128_GCM_NI_aes128_gcm_encrypt(ctx, 0, mac.data(), NULL, aad.size(), aad.data(), nonce.size(), nonce.data());
    KRML_HOST_FREE(ctx);
  }
}

BENCHMARK(HACL_AES_128_GCM_NI_aad)->Setup(DoSetup)->Apply(Range);
#endif

static void
HACL_AES_128_GCM_CT64_encrypt(benchmark::State& state)
{
  bytes plaintext(state.range(0), 0x37);
  bytes ciphertext(state.range(0) + 16, 0);
  
  for (auto _ : state) {
    uint64_t *ctx = (uint64_t *)KRML_HOST_CALLOC((uint32_t)928U, sizeof (uint8_t));
    Hacl_AES_128_GCM_CT64_aes128_gcm_init(ctx, key.data());
    Hacl_AES_128_GCM_CT64_aes128_gcm_encrypt(ctx, plaintext.size(), ciphertext.data(), plaintext.data(), 0, NULL, nonce.size(), nonce.data());
    KRML_HOST_FREE(ctx);
  }
}

BENCHMARK(HACL_AES_128_GCM_CT64_encrypt)->Setup(DoSetup)->Apply(Range);

static void
HACL_AES_128_GCM_CT64_aad(benchmark::State& state)
{
  bytes aad(state.range(0), 0x37);
  
  for (auto _ : state) {
    uint64_t *ctx = (uint64_t *)KRML_HOST_CALLOC((uint32_t)928U, sizeof (uint8_t));
    Hacl_AES_128_GCM_CT64_aes128_gcm_init(ctx, key.data());
    Hacl_AES_128_GCM_CT64_aes128_gcm_encrypt(ctx, 0, mac.data(), NULL, aad.size(), aad.data(), nonce.size(), nonce.data());
    KRML_HOST_FREE(ctx);
  }
}

BENCHMARK(HACL_AES_128_GCM_CT64_aad)->Setup(DoSetup)->Apply(Range);

static void
EverCrypt_AES128_GCM_encrypt(benchmark::State& state)
{
  bytes plaintext(state.range(0), 0x37);
  bytes ciphertext(state.range(0), 0);
  
  for (auto _ : state) {
    EverCrypt_AEAD_state_s* ctx;
    EverCrypt_Error_error_code res = EverCrypt_AEAD_create_in(
      Spec_Agile_AEAD_AES128_GCM, &ctx, key.data());

    if (res != EverCrypt_Error_Success) {
      state.SkipWithError("Could not allocate AEAD state.");
      break;
    }

    EverCrypt_AEAD_encrypt(ctx,
                           nonce.data(),
                           nonce.size(),
                           NULL,
                           0,
                           plaintext.data(),
                           plaintext.size(),
                           ciphertext.data(),
                           mac.data());

    EverCrypt_AEAD_free(ctx);
  }
}

BENCHMARK(EverCrypt_AES128_GCM_encrypt)->Setup(DoSetup)->Apply(Range);

static void
EverCrypt_AES128_GCM_aad(benchmark::State& state)
{
  bytes aad(state.range(0), 0x37);
  
  for (auto _ : state) {
    EverCrypt_AEAD_state_s* ctx;
    EverCrypt_Error_error_code res = EverCrypt_AEAD_create_in(
      Spec_Agile_AEAD_AES128_GCM, &ctx, key.data());

    if (res != EverCrypt_Error_Success) {
      state.SkipWithError("Could not allocate AEAD state.");
      break;
    }

    EverCrypt_AEAD_encrypt(ctx,
                           nonce.data(),
                           nonce.size(),
                           aad.data(),
                           aad.size(),
                           NULL,
                           0,
                           NULL,
                           mac.data());

    EverCrypt_AEAD_free(ctx);
  }
}

BENCHMARK(EverCrypt_AES128_GCM_aad)->Setup(DoSetup)->Apply(Range);

#ifndef NO_OPENSSL
static void
OpenSSL_aes_128_gcm_encrypt(benchmark::State& state)
{
  bytes plaintext(state.range(0), 0x37);
  bytes ciphertext(state.range(0), 0);
  
  for (auto _ : state) {
    int out_len, unused_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int result = EVP_EncryptInit_ex2(
      ctx, EVP_aes_128_gcm(), key.data(), nonce.data(), NULL);
    if (result != 1) {
      state.SkipWithError("");
      EVP_CIPHER_CTX_free(ctx);
      break;
    }
    result = EVP_EncryptUpdate(
      ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size());
    if (result != 1) {
      state.SkipWithError("");
      EVP_CIPHER_CTX_free(ctx);
      break;
    }
    result = EVP_EncryptFinal_ex(ctx, mac.data(), &unused_len);
    if (result != 1 || unused_len != 0) {
      state.SkipWithError("");
      EVP_CIPHER_CTX_free(ctx);
      break;
    }
    EVP_CIPHER_CTX_free(ctx);
  }
}

BENCHMARK(OpenSSL_aes_128_gcm_encrypt)->Setup(DoSetup)->Apply(Range);

static void
OpenSSL_aes_128_gcm_aad(benchmark::State& state)
{
  bytes aad(state.range(0), 0x37);
  
  for (auto _ : state) {
    int out_len, unused_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int result = EVP_EncryptInit_ex2(
      ctx, EVP_aes_128_gcm(), key.data(), nonce.data(), NULL);
    if (result != 1) {
      state.SkipWithError("");
      EVP_CIPHER_CTX_free(ctx);
      break;
    }
    result = EVP_EncryptUpdate(
      ctx, NULL, &out_len, aad.data(), aad.size());
    if (result != 1) {
      state.SkipWithError("");
      EVP_CIPHER_CTX_free(ctx);
      break;
    }
    result = EVP_EncryptFinal_ex(ctx, mac.data(), &unused_len);
    if (result != 1 || unused_len != 0) {
      state.SkipWithError("");
      EVP_CIPHER_CTX_free(ctx);
      break;
    }
    EVP_CIPHER_CTX_free(ctx);
  }
}

BENCHMARK(OpenSSL_aes_128_gcm_aad)->Setup(DoSetup)->Apply(Range);
#endif

static void
BearSSL_CT64_AES128_GCM_encrypt(benchmark::State& state)
{
  bytes plaintext(state.range(0), 0x37);
  
  for (auto _ : state) {
    br_aes_ct64_ctr_keys bc;
    br_gcm_context gc;
    br_aes_ct64_ctr_init(&bc, key.data(), key.size());
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul64);

    br_gcm_reset(&gc, nonce.data(), nonce.size());
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 1, plaintext.data(), plaintext.size());
    br_gcm_get_tag(&gc, mac.data());
  }
}

BENCHMARK(BearSSL_CT64_AES128_GCM_encrypt)->Setup(DoSetup)->Apply(Range);

static void
BearSSL_CT64_AES128_GCM_aad(benchmark::State& state)
{
  bytes aad(state.range(0), 0x37);
  
  for (auto _ : state) {
    br_aes_ct64_ctr_keys bc;
    br_gcm_context gc;
    br_aes_ct64_ctr_init(&bc, key.data(), key.size());
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul64);

    br_gcm_reset(&gc, nonce.data(), nonce.size());
    br_gcm_aad_inject(&gc, aad.data(), aad.size());
    br_gcm_get_tag(&gc, mac.data());
  }
}

BENCHMARK(BearSSL_CT64_AES128_GCM_aad)->Setup(DoSetup)->Apply(Range);

BENCHMARK_MAIN();
