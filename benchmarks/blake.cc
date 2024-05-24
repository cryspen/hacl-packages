/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "EverCrypt_Hash.h"
#include "Hacl_Hash_Blake2b.h"
#include "Hacl_Hash_Blake2s.h"

#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_Simd128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_Simd256.h"
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
    Hacl_Hash_Blake2b_hash_with_key(
      digest2b.data(), digest2b.size(), (uint8_t*)input.data(), input.size(),
      NULL, 0);
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
    Hacl_Hash_Blake2b_Simd256_hash_with_key(
      digest2b.data(), digest2b.size(), (uint8_t*)input.data(), input.size(),
      NULL, 0);
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
      digest2b.data(), input.data(), input.size());
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

#ifndef NO_LIBB2
#include <blake2.h>

static void
libb2_blake2b_oneshot(benchmark::State& state)
{
  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
      blake2b(digest2b.data(), (const void*)input.data(), NULL, digest2b.size(), input.size(), 0);
  }
}

BENCHMARK(libb2_blake2b_oneshot)->Setup(DoSetup)->Apply(Range);
#endif

// -----------------------------------------------------------------------------

static void
HACL_blake2b_32_oneshot_keyed(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_Blake2b_hash_with_key(
      digest2b.data(), digest2b.size(), (uint8_t*)input.data(), input.size(),
      key.data(), key.size());
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
    Hacl_Hash_Blake2b_Simd256_hash_with_key(
      digest2b.data(), digest2b.size(), (uint8_t*)input.data(), input.size(),
      key.data(), key.size());
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

#ifndef NO_LIBB2
#include <blake2.h>

static void
libb2_blake2b_oneshot_keyed(benchmark::State& state)
{
  for (auto _ : state)
    blake2b(digest2b.data(), (const void*)input.data(), (const void*)key.data(), digest2b.size(), input.size(), key.size());
}

BENCHMARK(libb2_blake2b_oneshot_keyed)->Setup(DoSetup);
#endif


// -----------------------------------------------------------------------------

static void
HACL_blake2s_32_oneshot(benchmark::State& state)
{
  bytes input(state.range(0), 0xAB);

  for (auto _ : state) {
    Hacl_Hash_Blake2s_hash_with_key(
      digest2s.data(), digest2s.size(), input.data(), input.size(), NULL, 0);
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
    Hacl_Hash_Blake2s_Simd128_hash_with_key(
      digest2s.data(), digest2s.size(), input.data(), input.size(), NULL, 0);
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
      digest2s.data(), input.data(), input.size());
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

#ifndef NO_LIBB2
#include <blake2.h>

static void
libb2_blake2s_oneshot(benchmark::State& state)
{
  bytes input(state.range(0), 0xAB);

  for (auto _ : state)
    blake2s(digest2s.data(), (const void*)input.data(), NULL, digest2s.size(), input.size(), 0);
}

BENCHMARK(libb2_blake2s_oneshot)->Setup(DoSetup)->Apply(Range);
#endif

// -----------------------------------------------------------------------------

static void
HACL_blake2s_32_oneshot_keyed(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_Blake2s_hash_with_key(
      digest2s.data(), digest2s.size(), (uint8_t*)input.data(), input.size(),
      key.data(), key.size());
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
    Hacl_Hash_Blake2s_Simd128_hash_with_key(
      digest2s.data(), digest2s.size(), (uint8_t*)input.data(), input.size(),
      key.data(), key.size());
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

#ifndef NO_LIBB2
#include <blake2.h>

static void
libb2_blake2s_oneshot_keyed(benchmark::State& state)
{
  for (auto _ : state)
    blake2s(digest2s.data(), (const void*)input.data(), (const void*)key.data(), digest2s.size(), input.size(), key.size());
}

BENCHMARK(libb2_blake2s_oneshot_keyed)->Setup(DoSetup);
#endif


// -----------------------------------------------------------------------------

static void
HACL_blake2b_32_streaming(benchmark::State& state)
{
  for (auto _ : state) {
    uint8_t digest[HACL_HASH_BLAKE2B_DIGEST_LENGTH_MAX];

    // Init
    Hacl_Hash_Blake2b_state_t* ctx =
      Hacl_Hash_Blake2b_malloc();

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Hash_Blake2b_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Hash_Blake2b_digest(ctx, digest);
    Hacl_Hash_Blake2b_free(ctx);
  }
}

BENCHMARK(HACL_blake2b_32_streaming)->Setup(DoSetup);

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
    Hacl_Hash_Blake2b_Simd256_state_t* ctx =
      Hacl_Hash_Blake2b_Simd256_malloc();

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Hash_Blake2b_Simd256_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Hash_Blake2b_Simd256_digest(ctx, digest);
    Hacl_Hash_Blake2b_Simd256_free(ctx);
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
    EverCrypt_Hash_Incremental_state_t* ctx =
      EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_Blake2B);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      EverCrypt_Hash_Incremental_update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    EverCrypt_Hash_Incremental_digest(ctx, digest);
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
    Hacl_Hash_Blake2s_state_t* ctx = Hacl_Hash_Blake2s_malloc();

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Hash_Blake2s_update(ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Hash_Blake2s_digest(ctx, digest);
    Hacl_Hash_Blake2s_free(ctx);
  }
}

BENCHMARK(HACL_blake2s_32_streaming)->Setup(DoSetup);

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
    Hacl_Hash_Blake2s_Simd128_state_t* ctx = Hacl_Hash_Blake2s_Simd128_malloc();

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      Hacl_Hash_Blake2s_Simd128_update(
        ctx, (uint8_t*)chunk.data(), chunk.size());
    }

    // Finish
    Hacl_Hash_Blake2s_Simd128_digest(ctx, digest);
    Hacl_Hash_Blake2s_Simd128_free(ctx);
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
    EverCrypt_Hash_Incremental_state_t* ctx =
      EverCrypt_Hash_Incremental_malloc(Spec_Hash_Definitions_Blake2S);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      EverCrypt_Hash_Incremental_update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    EverCrypt_Hash_Incremental_digest(ctx, digest);
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
