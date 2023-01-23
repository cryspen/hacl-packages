/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */
#include "util.h"

#include "EverCrypt_Hash.h"
#include "Hacl_Hash_Blake2.h"
#include "Hacl_Streaming_Blake2.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#include "Hacl_Streaming_Blake2s_128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_256.h"
#include "Hacl_Streaming_Blake2b_256.h"
#endif

#define HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX 64
#define HACL_HASH_BLAKE2S_DIGEST_LENGTH_MAX 32

static bytes input(1000, 0x37);
static bytes key(64, 0x72);
static bytes digest2b(64, 0);
static bytes digest2s(32, 0);

// Blake2b 32-bit keyed
static void
Blake2b_32_keyed(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_Blake2b_32_blake2b(digest2b.size(),
                            digest2b.data(),
                            input.size(),
                            input.data(),
                            key.size(),
                            key.data());
  }
}

BENCHMARK(Blake2b_32_keyed);

// Blake2b 32-bit
static void
Blake2b_32(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_Blake2b_32_blake2b(
      digest2b.size(), digest2b.data(), input.size(), input.data(), 0, NULL);
  }
}

BENCHMARK(Blake2b_32);

// Blake2b vec256
#ifdef HACL_CAN_COMPILE_VEC256
static void
Blake2b_vec256_keyed(benchmark::State& state)
{
  cpu_init();
  if (!vec256_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  for (auto _ : state) {
    Hacl_Blake2b_256_blake2b(digest2b.size(),
                             digest2b.data(),
                             input.size(),
                             input.data(),
                             key.size(),
                             key.data());
  }
}

BENCHMARK(Blake2b_vec256_keyed);

static void
Blake2b_vec256(benchmark::State& state)
{
  cpu_init();
  if (!vec256_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  for (auto _ : state) {
    Hacl_Blake2b_256_blake2b(
      digest2b.size(), digest2b.data(), input.size(), input.data(), 0, NULL);
  }
}

BENCHMARK(Blake2b_vec256);
#endif // HACL_CAN_COMPILE_VEC256

// Evercrypt Blake2b
static void
Blake2b_Evercrypt(benchmark::State& state)
{
  while (state.KeepRunning()) {
    EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_Blake2B,
                                    digest2b.data(),
                                    input.data(),
                                    input.size());
  }
}

BENCHMARK(Blake2b_Evercrypt);

#ifndef NO_OPENSSL
// OpenSSL Blake2b
static void
Openssl_Blake2b(benchmark::State& state)
{
  while (state.KeepRunning()) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex2(mdctx, EVP_blake2b512(), NULL) != 1) {
      state.SkipWithError("Error in EVP_DigestInit_ex2");
      EVP_MD_CTX_free(mdctx);
      break;
    }
    if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1) {
      state.SkipWithError("Error in EVP_DigestUpdate");
      EVP_MD_CTX_free(mdctx);
      break;
    }
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(mdctx, digest2b.data(), &md_len) != 1 ||
        md_len != 64) {
      state.SkipWithError("Error in EVP_DigestFinal_ex");
      EVP_MD_CTX_free(mdctx);
      break;
    }
    EVP_MD_CTX_free(mdctx);
  }
}

BENCHMARK(Openssl_Blake2b);
#endif

// Blake2b 32-bit | streaming
static void
Blake2b_32_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Streaming_Blake2_blake2b_32_state_s* ctx =
      Hacl_Streaming_Blake2_blake2b_32_no_key_create_in();
    Hacl_Streaming_Blake2_blake2b_32_no_key_init(ctx);

    // Update
    for (auto chunk : chunk(input, 7)) {
      Hacl_Streaming_Blake2_blake2b_32_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2_blake2b_32_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2_blake2b_32_no_key_free(ctx);
  }
}

BENCHMARK(Blake2b_32_streaming);

#ifdef HACL_CAN_COMPILE_VEC256
// Blake2b vec256 | streaming
static void
Blake2b_vec256_streaming(benchmark::State& state)
{
  cpu_init();
  if (!vec256_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Streaming_Blake2b_256_blake2b_256_state_s* ctx =
      Hacl_Streaming_Blake2b_256_blake2b_256_no_key_create_in();
    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_init(ctx);

    // Update
    for (auto chunk : chunk(input, 7)) {
      Hacl_Streaming_Blake2b_256_blake2b_256_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_free(ctx);
  }
}

BENCHMARK(Blake2b_vec256_streaming);
#endif

// Blake2b EverCrypt | streaming
static void
Blake2b_EverCrypt_streaming(benchmark::State& state)
{
  cpu_init();
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // Init
    EverCrypt_Hash_Incremental_hash_state_s* ctx =
      EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_Blake2B);
    EverCrypt_Hash_Incremental_init(ctx);

    // Update
    for (auto chunk : chunk(input, 7)) {
      EverCrypt_Hash_Incremental_update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    EverCrypt_Hash_Incremental_finish(ctx, digest);
    EverCrypt_Hash_Incremental_free(ctx);
  }
}

BENCHMARK(Blake2b_EverCrypt_streaming);

// -----------------------------------------------------------------------------

// Blake2s 32-bit keyed
static void
Blake2s_32_keyed(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Blake2s_32_blake2s(digest2s.size(),
                            digest2s.data(),
                            input.size(),
                            input.data(),
                            key.size(),
                            key.data());
  }
}

BENCHMARK(Blake2s_32_keyed);

// Blake2s 32-bit
static void
Blake2s_32(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Blake2s_32_blake2s(
      digest2s.size(), digest2s.data(), input.size(), input.data(), 0, NULL);
  }
}

BENCHMARK(Blake2s_32);

// Blake2s vec128
#ifdef HACL_CAN_COMPILE_VEC128
static void
Blake2s_vec128_keyed(benchmark::State& state)
{
  cpu_init();
  if (!vec128_support()) {
    state.SkipWithError("No vec128 support");
    return;
  }

  for (auto _ : state) {
    Hacl_Blake2s_128_blake2s(digest2s.size(),
                             digest2s.data(),
                             input.size(),
                             input.data(),
                             key.size(),
                             key.data());
  }
}

BENCHMARK(Blake2s_vec128_keyed);

static void
Blake2s_vec128(benchmark::State& state)
{
  cpu_init();
  if (!vec128_support()) {
    state.SkipWithError("No vec128 support");
    return;
  }

  for (auto _ : state) {
    Hacl_Blake2s_128_blake2s(
      digest2s.size(), digest2s.data(), input.size(), input.data(), 0, NULL);
  }
}

BENCHMARK(Blake2s_vec128);
#endif // HACL_CAN_COMPILE_VEC128

// Evercrypt Blake2s
static void
Blake2s_Evercrypt(benchmark::State& state)
{
  EverCrypt_AutoConfig2_init();
  while (state.KeepRunning()) {
    EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_Blake2S,
                                    digest2s.data(),
                                    input.data(),
                                    input.size());
  }
}

BENCHMARK(Blake2s_Evercrypt);

#ifndef NO_OPENSSL
// OpenSSL Blake2s
static void
Openssl_Blake2s(benchmark::State& state)
{
  while (state.KeepRunning()) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex2(mdctx, EVP_blake2s256(), NULL) != 1) {
      state.SkipWithError("Error in EVP_DigestInit_ex2");
      EVP_MD_CTX_free(mdctx);
      break;
    }
    if (EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1) {
      state.SkipWithError("Error in EVP_DigestUpdate");
      EVP_MD_CTX_free(mdctx);
      break;
    }
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(mdctx, digest2s.data(), &md_len) != 1 ||
        md_len != 32) {
      state.SkipWithError("Error in EVP_DigestFinal_ex");
      EVP_MD_CTX_free(mdctx);
      break;
    }
    EVP_MD_CTX_free(mdctx);
  }
}

BENCHMARK(Openssl_Blake2s);
#endif

// Blake2s 32-bit | streaming
static void
Blake2s_32_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2S_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Streaming_Blake2_blake2s_32_state_s* ctx =
      Hacl_Streaming_Blake2_blake2s_32_no_key_create_in();
    Hacl_Streaming_Blake2_blake2s_32_no_key_init(ctx);

    // Update
    for (auto chunk : chunk(input, 7)) {
      Hacl_Streaming_Blake2_blake2s_32_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2_blake2s_32_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2_blake2s_32_no_key_free(ctx);
  }
}

BENCHMARK(Blake2s_32_streaming);

#ifdef HACL_CAN_COMPILE_VEC128
// Blake2s vec128 | streaming
static void
Blake2s_vec128_streaming(benchmark::State& state)
{
  cpu_init();
  if (!vec128_support()) {
    state.SkipWithError("No vec128 support");
    return;
  }

  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2S_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Streaming_Blake2s_128_blake2s_128_state_s* ctx =
      Hacl_Streaming_Blake2s_128_blake2s_128_no_key_create_in();
    Hacl_Streaming_Blake2s_128_blake2s_128_no_key_init(ctx);

    // Update
    for (auto chunk : chunk(input, 7)) {
      Hacl_Streaming_Blake2s_128_blake2s_128_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2s_128_blake2s_128_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2s_128_blake2s_128_no_key_free(ctx);
  }
}

BENCHMARK(Blake2s_vec128_streaming);
#endif

// Blake2s EverCrypt | streaming
static void
Blake2s_EverCrypt_streaming(benchmark::State& bm_state)
{
  cpu_init();
  for (auto _ : bm_state) {
    uint8_t digest[HACL_HASH_BLAKE2S_DIGEST_LENGTH_MAX];

    // Init
    EverCrypt_Hash_Incremental_hash_state_s* ctx =
      EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_Blake2S);
    EverCrypt_Hash_Incremental_init(ctx);

    // Update
    for (auto chunk : chunk(input, 7)) {
      EverCrypt_Hash_Incremental_update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    EverCrypt_Hash_Incremental_finish(ctx, digest);
    EverCrypt_Hash_Incremental_free(ctx);
  }
}

BENCHMARK(Blake2s_EverCrypt_streaming);

BENCHMARK_MAIN();
