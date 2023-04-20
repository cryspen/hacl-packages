/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "EverCrypt_Hash.h"
#include "Hacl_Hash_Blake2.h"
#include "Hacl_Streaming_Blake2.h"

#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#include "Hacl_Streaming_Blake2s_128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_256.h"
#include "Hacl_Streaming_Blake2b_256.h"
#endif

#include "blake2.h"

#define HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX 64
#define HACL_HASH_BLAKE2S_DIGEST_LENGTH_MAX 32

const bytes input(1000, 0x37);

static bytes key(64, 0x72);
static bytes digest2b(64, 0);
static bytes digest2s(32, 0);

const size_t chunk_len = 135;

const bytes expected_digest_blake2b512 =
  from_hex("f70070628cf99c5f67f56079024f952a7a4f58b7a0e1c9bff1962502bc2ae1eb2ec"
           "f12d5249461e8efe27a58c0c9a549ccb4506cc9f986226e69e7be98ae27a1");
const bytes expected_digest_blake2s256 =
  from_hex("1b472dff2aec94842fc209bf6f0f922a330e2da17c4464ef06e5035c3f1cf1e4");

static void
HACL_blake2b_32_oneshot(benchmark::State& state)
{
  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
    Hacl_Blake2b_32_blake2b(digest2b.size(),
                            digest2b.data(),
                            input.size(),
                            (uint8_t*)input.data(),
                            0,
                            NULL);
  }
}

BENCHMARK(HACL_blake2b_32_oneshot)->Setup(DoSetup)->Apply(Range);

#ifdef HACL_CAN_COMPILE_VEC256
static void
HACL_blake2b_vec256_oneshot(benchmark::State& state)
{
  if (!vec256_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
    Hacl_Blake2b_256_blake2b(digest2b.size(),
                             digest2b.data(),
                             input.size(),
                             (uint8_t*)input.data(),
                             0,
                             NULL);
  }
}

BENCHMARK(HACL_blake2b_vec256_oneshot)->Setup(DoSetup)->Apply(Range);
#endif

static void
EverCrypt_blake2b_oneshot(benchmark::State& state)
{
  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
    EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_Blake2B,
                                    digest2b.data(),
                                    input.data(),
                                    input.size());
  }
}

BENCHMARK(EverCrypt_blake2b_oneshot)->Setup(DoSetup)->Apply(Range);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  blake2b512,
                  EVP_blake2b512(),
                  input,
                  digest2b.size(),
                  expected_digest_blake2b512)
  ->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_blake2b_32_oneshot_keyed(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Blake2b_32_blake2b(digest2b.size(),
                            digest2b.data(),
                            input.size(),
                            (uint8_t*)input.data(),
                            key.size(),
                            key.data());
  }
}

BENCHMARK(HACL_blake2b_32_oneshot_keyed)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
HACL_blake2b_vec256_oneshot_keyed(benchmark::State& state)
{
  if (!vec256_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  for (auto _ : state) {
    Hacl_Blake2b_256_blake2b(digest2b.size(),
                             digest2b.data(),
                             input.size(),
                             (uint8_t*)input.data(),
                             key.size(),
                             key.data());
  }
}

BENCHMARK(HACL_blake2b_vec256_oneshot_keyed)->Setup(DoSetup);
#endif

static void
EverCrypt_blake2b_oneshot_keyed(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(EverCrypt_blake2b_oneshot_keyed)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_blake2b_oneshot_keyed(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(OpenSSL_blake2b_oneshot_keyed)->Setup(DoSetup);
#endif


// -----------------------------------------------------------------------------

static void
HACL_blake2s_32_oneshot(benchmark::State& state)
{
  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
    Hacl_Blake2s_32_blake2s(
      digest2s.size(), digest2s.data(), input.size(), input.data(), 0, NULL);
  }
}

BENCHMARK(HACL_blake2s_32_oneshot)->Setup(DoSetup)->Apply(Range);

#ifdef HACL_CAN_COMPILE_VEC128
static void
HACL_blake2s_vec128_oneshot(benchmark::State& state)
{
  if (!vec128_support()) {
    state.SkipWithError("No vec128 support");
    return;
  }

  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
    Hacl_Blake2s_128_blake2s(
      digest2s.size(), digest2s.data(), input.size(), input.data(), 0, NULL);
  }
}

BENCHMARK(HACL_blake2s_vec128_oneshot)->Setup(DoSetup)->Apply(Range);
#endif

static void
EverCrypt_blake2s_oneshot(benchmark::State& state)
{
  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
    EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_Blake2S,
                                    digest2s.data(),
                                    input.data(),
                                    input.size());
  }
}

BENCHMARK(EverCrypt_blake2s_oneshot)->Setup(DoSetup)->Apply(Range);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  blake2s256,
                  EVP_blake2s256(),
                  input,
                  digest2s.size(),
                  expected_digest_blake2s256)
  ->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_blake2s_32_oneshot_keyed(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Blake2s_32_blake2s(digest2s.size(),
                            digest2s.data(),
                            input.size(),
                            (uint8_t*)input.data(),
                            key.size(),
                            key.data());
  }
}

BENCHMARK(HACL_blake2s_32_oneshot_keyed)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC128
static void
HACL_blake2s_vec128_oneshot_keyed(benchmark::State& state)
{
  if (!vec128_support()) {
    state.SkipWithError("No vec128 support");
    return;
  }

  for (auto _ : state) {
    Hacl_Blake2s_128_blake2s(digest2s.size(),
                             digest2s.data(),
                             input.size(),
                             (uint8_t*)input.data(),
                             key.size(),
                             key.data());
  }
}

BENCHMARK(HACL_blake2s_vec128_oneshot_keyed)->Setup(DoSetup);
#endif

static void
EverCrypt_blake2s_oneshot_keyed(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(EverCrypt_blake2s_oneshot_keyed)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_blake2s_oneshot_keyed(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(OpenSSL_blake2s_oneshot_keyed)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_blake2b_32_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Streaming_Blake2_blake2b_32_state_s* ctx =
      Hacl_Streaming_Blake2_blake2b_32_no_key_create_in();
    Hacl_Streaming_Blake2_blake2b_32_no_key_init(ctx);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Streaming_Blake2_blake2b_32_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2_blake2b_32_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2_blake2b_32_no_key_free(ctx);
  }
}

BENCHMARK(HACL_blake2b_32_streaming)->Setup(DoSetup);

static void
BLAKE2_blake2b_ref_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[64];

    // Init
    blake2b_state s;
    blake2b_init(&s,64);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      blake2b_update(&s, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    blake2b_final(&s,digest,64);
  }
}

BENCHMARK(BLAKE2_blake2b_ref_streaming)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
HACL_blake2b_vec256_streaming(benchmark::State& state)
{
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
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Streaming_Blake2b_256_blake2b_256_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2b_256_blake2b_256_no_key_free(ctx);
  }
}

BENCHMARK(HACL_blake2b_vec256_streaming)->Setup(DoSetup);
#endif

static void
EverCrypt_blake2b_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // Init
    EverCrypt_Hash_Incremental_hash_state_s* ctx =
      EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_Blake2B);
    EverCrypt_Hash_Incremental_init(ctx);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      EverCrypt_Hash_Incremental_update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    EverCrypt_Hash_Incremental_finish(ctx, digest);
    EverCrypt_Hash_Incremental_free(ctx);
  }
}

BENCHMARK(EverCrypt_blake2b_streaming)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  blake2b512,
                  EVP_blake2b512(),
                  input,
                  chunk_len,
                  digest2b.size(),
                  expected_digest_blake2b512)
  ->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_blake2s_32_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2S_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Streaming_Blake2_blake2s_32_state_s* ctx =
      Hacl_Streaming_Blake2_blake2s_32_no_key_create_in();
    Hacl_Streaming_Blake2_blake2s_32_no_key_init(ctx);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Streaming_Blake2_blake2s_32_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2_blake2s_32_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2_blake2s_32_no_key_free(ctx);
  }
}

BENCHMARK(HACL_blake2s_32_streaming)->Setup(DoSetup);

static void
BLAKE2_blake2s_ref_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[32];

    // Init
    blake2s_state s;
    blake2s_init(&s,32);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      blake2s_update(&s, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    blake2s_final(&s,digest,32);
  }
}

BENCHMARK(BLAKE2_blake2s_ref_streaming)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC128
static void
HACL_blake2s_vec128_streaming(benchmark::State& state)
{
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
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Streaming_Blake2s_128_blake2s_128_no_key_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Streaming_Blake2s_128_blake2s_128_no_key_finish(ctx, digest);
    Hacl_Streaming_Blake2s_128_blake2s_128_no_key_free(ctx);
  }
}

BENCHMARK(HACL_blake2s_vec128_streaming)->Setup(DoSetup);
#endif

static void
EverCrypt_blake2s_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2S_DIGEST_LENGTH_MAX];

    // Init
    EverCrypt_Hash_Incremental_hash_state_s* ctx =
      EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_Blake2S);
    EverCrypt_Hash_Incremental_init(ctx);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      EverCrypt_Hash_Incremental_update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    EverCrypt_Hash_Incremental_finish(ctx, digest);
    EverCrypt_Hash_Incremental_free(ctx);
  }
}

BENCHMARK(EverCrypt_blake2s_streaming)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  blake2s256,
                  EVP_blake2s256(),
                  input,
                  chunk_len,
                  digest2s.size(),
                  expected_digest_blake2s256)
  ->Setup(DoSetup);

#endif

BENCHMARK_MAIN();
