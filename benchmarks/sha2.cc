/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */
#include "EverCrypt_Hash.h"
#include "Hacl_Hash_SHA2.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_Simd128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_Simd256.h"
#endif

#include "util.h"

#define HACL_HASH_SHA2_224_DIGEST_LENGTH 28
#define HACL_HASH_SHA2_256_DIGEST_LENGTH 32
#define HACL_HASH_SHA2_384_DIGEST_LENGTH 48
#define HACL_HASH_SHA2_512_DIGEST_LENGTH 64

const bytes input(1000, 0x37);
const bytes expected_digest_sha2_224 =
  from_hex("07cdbd2503e3f3124311f65efafcb4eaae28b60b6bd75d06389848b7");
const bytes expected_digest_sha2_256 =
  from_hex("2fb8ebc720944eeb80c783813f870f3bbc20353e4d5714dea88ec06395503876");
const bytes expected_digest_sha2_384 =
  from_hex("1c475d9b7c90e8b9d5ce6ead1e4bf65ae872a6d4aa9801d9c3c6e54f45ea78da76b"
           "c944ceae6f0314d006b1c8cb6c5f1");
const bytes expected_digest_sha2_512 =
  from_hex("e9e2fa1ce6756fabc5b49f765a48175ec431377ccfadbcfe18795fc6c868805b0c9"
           "4ce67d06d7823fb7afef3fd5cc8b7057912ec289e0481220bc54019f86501");

const size_t chunk_len = 135;

template<class... Args>
void
HACL_Sha2_oneshot(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);

  auto digest_len = std::get<0>(args_tuple);
  auto expected_digest = std::get<1>(args_tuple);
  auto hash = std::get<2>(args_tuple);

  bytes output(digest_len, 0);

  for (auto _ : state) {
    hash(output.data(), (uint8_t*)input.data(), input.size());
  }

  if (output != expected_digest) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

template<class... Args>
void
EverCrypt_Sha2_oneshot(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);

  auto algorithm = std::get<0>(args_tuple);
  auto expected_digest = std::get<1>(args_tuple);

  auto digest_len = EverCrypt_Hash_Incremental_hash_len(algorithm);
  bytes digest(digest_len, 0);

  for (auto _ : state) {
    EverCrypt_Hash_Incremental_hash(
      algorithm, digest.data(), (uint8_t*)input.data(), input.size());
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

template<class... Args>
void
HACL_Sha2_streaming(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);

  auto digest_len = std::get<0>(args_tuple);
  auto expected_digest = std::get<1>(args_tuple);
  auto malloc = std::get<2>(args_tuple);
  //auto reset = std::get<3>(args_tuple);
  auto update = std::get<4>(args_tuple);
  auto digest = std::get<5>(args_tuple);
  auto free = std::get<6>(args_tuple);

  bytes output(digest_len, 0);

  for (auto _ : state) {
    // Init
    auto* ctx = malloc();

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    digest(ctx, output.data());
    free(ctx);
  }

  if (output != expected_digest) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

template<class... Args>
void
EverCrypt_Sha2_streaming(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);

  auto algorithm = std::get<0>(args_tuple);
  auto expected_digest = std::get<1>(args_tuple);

  auto digest_len = EverCrypt_Hash_Incremental_hash_len(algorithm);
  bytes digest(digest_len, 0);

  for (auto _ : state) {
    // Init
    EverCrypt_Hash_Incremental_state_t* ctx =
      EverCrypt_Hash_Incremental_malloc(algorithm);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      EverCrypt_Hash_Incremental_update(ctx, chunk.data(), chunk.size());
    }

    // Finish
    EverCrypt_Hash_Incremental_digest(ctx, digest.data());
    EverCrypt_Hash_Incremental_free(ctx);
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

// -----------------------------------------------------------------------------

BENCHMARK_CAPTURE(HACL_Sha2_oneshot,
                  sha2_224,
                  HACL_HASH_SHA2_224_DIGEST_LENGTH,
                  expected_digest_sha2_224,
                  Hacl_Hash_SHA2_hash_224)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_oneshot,
                  sha2_224,
                  Spec_Hash_Definitions_SHA2_224,
                  expected_digest_sha2_224)
  ->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha2_224,
                  EVP_sha224(),
                  input,
                  HACL_HASH_SHA2_224_DIGEST_LENGTH,
                  expected_digest_sha2_224)
  ->Setup(DoSetup);
#endif

BENCHMARK_CAPTURE(HACL_Sha2_oneshot,
                  sha2_256,
                  HACL_HASH_SHA2_256_DIGEST_LENGTH,
                  expected_digest_sha2_256,
                  Hacl_Hash_SHA2_hash_256)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_oneshot,
                  sha2_256,
                  Spec_Hash_Definitions_SHA2_256,
                  expected_digest_sha2_256)
  ->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha2_256,
                  EVP_sha256(),
                  input,
                  HACL_HASH_SHA2_256_DIGEST_LENGTH,
                  expected_digest_sha2_256)
  ->Setup(DoSetup);
#endif

BENCHMARK_CAPTURE(HACL_Sha2_oneshot,
                  sha2_384,
                  HACL_HASH_SHA2_384_DIGEST_LENGTH,
                  expected_digest_sha2_384,
                  Hacl_Hash_SHA2_hash_384)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_oneshot,
                  sha2_384,
                  Spec_Hash_Definitions_SHA2_384,
                  expected_digest_sha2_384)
  ->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha2_384,
                  EVP_sha384(),
                  input,
                  HACL_HASH_SHA2_384_DIGEST_LENGTH,
                  expected_digest_sha2_384)
  ->Setup(DoSetup);
#endif

BENCHMARK_CAPTURE(HACL_Sha2_oneshot,
                  sha2_512,
                  HACL_HASH_SHA2_512_DIGEST_LENGTH,
                  expected_digest_sha2_512,
                  Hacl_Hash_SHA2_hash_512)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_oneshot,
                  sha2_512,
                  Spec_Hash_Definitions_SHA2_512,
                  expected_digest_sha2_512)
  ->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha2_512,
                  EVP_sha512(),
                  input,
                  HACL_HASH_SHA2_512_DIGEST_LENGTH,
                  expected_digest_sha2_512)
  ->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

BENCHMARK_CAPTURE(HACL_Sha2_streaming,
                  sha2_224,
                  HACL_HASH_SHA2_224_DIGEST_LENGTH,
                  expected_digest_sha2_224,
                  Hacl_Hash_SHA2_malloc_224,
                  Hacl_Hash_SHA2_reset_224,
                  Hacl_Hash_SHA2_update_224,
                  Hacl_Hash_SHA2_digest_224,
                  Hacl_Hash_SHA2_free_224)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_streaming,
                  sha2_224,
                  Spec_Hash_Definitions_SHA2_224,
                  expected_digest_sha2_224)
  ->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha2_224,
                  EVP_sha224(),
                  input,
                  chunk_len,
                  HACL_HASH_SHA2_224_DIGEST_LENGTH,
                  expected_digest_sha2_224)
  ->Setup(DoSetup);
#endif

BENCHMARK_CAPTURE(HACL_Sha2_streaming,
                  sha2_256,
                  HACL_HASH_SHA2_256_DIGEST_LENGTH,
                  expected_digest_sha2_256,
                  Hacl_Hash_SHA2_malloc_256,
                  Hacl_Hash_SHA2_reset_256,
                  Hacl_Hash_SHA2_update_256,
                  Hacl_Hash_SHA2_digest_256,
                  Hacl_Hash_SHA2_free_256)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_streaming,
                  sha2_256,
                  Spec_Hash_Definitions_SHA2_256,
                  expected_digest_sha2_256)
  ->Setup(DoSetup);

#include "sha256.h"

static void
Digestif_sha256(benchmark::State& state)
{
  bytes digest(32, 0);

  for (auto _ : state) {

    sha256_ctx ctx;
    digestif_sha256_init(&ctx);

    for (auto chunk : chunk(input, chunk_len)) {
      digestif_sha256_update(&ctx, chunk.data(), chunk.size());
    }

    digestif_sha256_finalize(&ctx, digest.data());

  }

  if (digest != expected_digest_sha2_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Digestif_sha256)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha2_256,
                  EVP_sha256(),
                  input,
                  chunk_len,
                  HACL_HASH_SHA2_256_DIGEST_LENGTH,
                  expected_digest_sha2_256)
  ->Setup(DoSetup);
#endif

BENCHMARK_CAPTURE(HACL_Sha2_streaming,
                  sha2_384,
                  HACL_HASH_SHA2_384_DIGEST_LENGTH,
                  expected_digest_sha2_384,
                  Hacl_Hash_SHA2_malloc_384,
                  Hacl_Hash_SHA2_reset_384,
                  Hacl_Hash_SHA2_update_384,
                  Hacl_Hash_SHA2_digest_384,
                  Hacl_Hash_SHA2_free_384)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_streaming,
                  sha2_384,
                  Spec_Hash_Definitions_SHA2_384,
                  expected_digest_sha2_384)
  ->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha2_384,
                  EVP_sha384(),
                  input,
                  chunk_len,
                  HACL_HASH_SHA2_384_DIGEST_LENGTH,
                  expected_digest_sha2_384)
  ->Setup(DoSetup);
#endif

BENCHMARK_CAPTURE(HACL_Sha2_streaming,
                  sha2_512,
                  HACL_HASH_SHA2_512_DIGEST_LENGTH,
                  expected_digest_sha2_512,
                  Hacl_Hash_SHA2_malloc_512,
                  Hacl_Hash_SHA2_reset_512,
                  Hacl_Hash_SHA2_update_512,
                  Hacl_Hash_SHA2_digest_512,
                  Hacl_Hash_SHA2_free_512)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(EverCrypt_Sha2_streaming,
                  sha2_512,
                  Spec_Hash_Definitions_SHA2_512,
                  expected_digest_sha2_512)
  ->Setup(DoSetup);

#include "sha512.h"

static void
Digestif_sha512(benchmark::State& state)
{
  bytes digest(64, 0);

  for (auto _ : state) {

    sha512_ctx ctx;
    digestif_sha512_init(&ctx);

    for (auto chunk : chunk(input, chunk_len)) {
      digestif_sha512_update(&ctx, chunk.data(), chunk.size());
    }

    digestif_sha512_finalize(&ctx, digest.data());

  }

  if (digest != expected_digest_sha2_512) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Digestif_sha512)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha2_512,
                  EVP_sha512(),
                  input,
                  chunk_len,
                  HACL_HASH_SHA2_512_DIGEST_LENGTH,
                  expected_digest_sha2_512)
  ->Setup(DoSetup);
#endif


// -----------------------------------------------------------------------------

#ifdef LIBTOMCRYPT
#include "tomcrypt.h"

static void
LibTomCrypt_Sha2_256(benchmark::State& state)
{
  bytes digest(32, 0);

  int err;

  for (auto _ : state) {
    hash_state md;
    sha256_init(&md);
    err = sha256_process(&md, input.data(), input.size());
    sha256_done(&md, digest.data());
  }

  if (err != CRYPT_OK || digest != expected_digest_sha2_256) {
    state.SkipWithError("Wrong libtomcrypt digest");
    return;
  }
}

BENCHMARK(LibTomCrypt_Sha2_256)->Setup(DoSetup);
#endif

BENCHMARK_MAIN();
