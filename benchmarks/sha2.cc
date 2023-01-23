/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */
#include "util.h"

#include "EverCrypt_Hash.h"
#include "Hacl_Streaming_SHA2.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_256.h"
#endif

static bytes input(1000, 0x37);
static bytes digest224(28, 0);
static bytes digest256(32, 0);
static bytes digest384(48, 0);
static bytes digest512(64, 0);

static void
Sha2_224_Streaming(benchmark::State& state)
{
  size_t chunk_len = 135;
  bytes non_streaming_digest224(28, 0);
  Hacl_Hash_SHA2_hash_224(
    input.data(), input.size(), non_streaming_digest224.data());

  while (state.KeepRunning()) {
    // Init
    Hacl_Streaming_SHA2_state_sha2_224* sha_state =
      Hacl_Streaming_SHA2_create_in_224();
    Hacl_Streaming_SHA2_init_224(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA2_update_224(
        sha_state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA2_finish_224(sha_state, digest224.data());
    Hacl_Streaming_SHA2_free_224(sha_state);
    if (non_streaming_digest224 != digest224) {
      state.SkipWithError("Wrong streaming digest");
      return;
    }
  }
}

static void
Sha2_256_Streaming(benchmark::State& state)
{
  size_t chunk_len = 135;
  bytes non_streaming_digest256(32, 0);
  Hacl_Hash_SHA2_hash_256(
    input.data(), input.size(), non_streaming_digest256.data());

  while (state.KeepRunning()) {
    // Init
    Hacl_Streaming_SHA2_state_sha2_224* sha_state =
      Hacl_Streaming_SHA2_create_in_256();
    Hacl_Streaming_SHA2_init_256(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA2_update_256(
        sha_state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA2_finish_256(sha_state, digest256.data());
    Hacl_Streaming_SHA2_free_256(sha_state);
    if (non_streaming_digest256 != digest256) {
      state.SkipWithError("Wrong streaming digest");
      return;
    }
  }
}

static void
Sha2_384_Streaming(benchmark::State& state)
{
  size_t chunk_len = 135;
  bytes non_streaming_digest384(digest384.size(), 0);
  Hacl_Hash_SHA2_hash_384(
    input.data(), input.size(), non_streaming_digest384.data());

  while (state.KeepRunning()) {
    // Init
    Hacl_Streaming_SHA2_state_sha2_384* sha_state =
      Hacl_Streaming_SHA2_create_in_384();
    Hacl_Streaming_SHA2_init_384(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA2_update_384(
        sha_state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA2_finish_384(sha_state, digest384.data());
    Hacl_Streaming_SHA2_free_384(sha_state);
    if (non_streaming_digest384 != digest384) {
      state.SkipWithError("Wrong streaming digest");
      return;
    }
  }
}

static void
Sha2_512_Streaming(benchmark::State& state)
{
  size_t chunk_len = 135;
  bytes non_streaming_digest512(digest512.size(), 0);
  Hacl_Hash_SHA2_hash_512(
    input.data(), input.size(), non_streaming_digest512.data());

  while (state.KeepRunning()) {
    // Init
    Hacl_Streaming_SHA2_state_sha2_512* sha_state =
      Hacl_Streaming_SHA2_create_in_512();
    Hacl_Streaming_SHA2_init_512(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA2_update_512(
        sha_state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA2_finish_512(sha_state, digest512.data());
    Hacl_Streaming_SHA2_free_512(sha_state);
    if (non_streaming_digest512 != digest512) {
      state.SkipWithError("Wrong streaming digest");
      return;
    }
  }
}

BENCHMARK(Sha2_224_Streaming);
BENCHMARK(Sha2_256_Streaming);
BENCHMARK(Sha2_384_Streaming);
BENCHMARK(Sha2_512_Streaming);

static void
Sha2_256(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_Hash_SHA2_hash_256(input.data(), input.size(), digest256.data());
  }
}

BENCHMARK(Sha2_256);

static void
EverCrypt_Sha2_256_Streaming(benchmark::State& state)
{
  cpu_init();
  size_t chunk_len = 135;
  bytes non_streaming_digest256(32, 0);
  Hacl_Hash_SHA2_hash_256(
    input.data(), input.size(), non_streaming_digest256.data());

  while (state.KeepRunning()) {
    // Init
    EverCrypt_Hash_Incremental_hash_state* sha_state =
      EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_256);
    EverCrypt_Hash_Incremental_init(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      EverCrypt_Hash_Incremental_update(
        sha_state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    EverCrypt_Hash_Incremental_finish(sha_state, digest256.data());
    EverCrypt_Hash_Incremental_free(sha_state);
    if (non_streaming_digest256 != digest256) {
      state.SkipWithError("Wrong streaming digest");
      return;
    }
  }
}

BENCHMARK(EverCrypt_Sha2_256_Streaming);

#ifdef LIBTOMCRYPT
// LibTomCrypt Sha2
#include "tomcrypt.h"
static void
LibTomCrypt_Sha2_256(benchmark::State& state)
{
  bytes hacl_digest256(32, 0);
  Hacl_Hash_SHA2_hash_256(input.data(), input.size(), hacl_digest256.data());
  while (state.KeepRunning()) {
    hash_state md;
    sha256_init(&md);
    int err = sha256_process(&md, input.data(), input.size());
    sha256_done(&md, digest256.data());
    if (err != CRYPT_OK || hacl_digest256 != digest256) {
      state.SkipWithError("Wrong libtomcrypt digest");
      return;
    }
  }
}

BENCHMARK(LibTomCrypt_Sha2_256);
#endif

#ifndef NO_OPENSSL
static void
OpenSSL_Sha2_256(benchmark::State& state)
{
  bytes hacl_digest256(32, 0);
  Hacl_Hash_SHA2_hash_256(input.data(), input.size(), hacl_digest256.data());
  while (state.KeepRunning()) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input.data(), input.size());
    SHA256_Final(digest256.data(), &ctx);
    if (hacl_digest256 != digest256) {
      state.SkipWithError("Wrong OpenSSL digest");
      return;
    }
  }
}

BENCHMARK(OpenSSL_Sha2_256);
#endif

BENCHMARK_MAIN();
