#include "util.h"

#include "Hacl_Hash_SHA3.h"
#include "Hacl_SHA3_Scalar.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_SHA3_Vec256.h"
#endif

const bytes input(1000, 0x37);

static bytes digest224_0(28, 0);
static bytes digest224_1(28, 0);
static bytes digest224_2(28, 0);
static bytes digest224_3(28, 0);
static bytes digest256_0(32, 0);
static bytes digest256_1(32, 0);
static bytes digest256_2(32, 0);
static bytes digest256_3(32, 0);
static bytes digest384_0(48, 0);
static bytes digest384_1(48, 0);
static bytes digest384_2(48, 0);
static bytes digest384_3(48, 0);
static bytes digest512_0(64, 0);
static bytes digest512_1(64, 0);
static bytes digest512_2(64, 0);
static bytes digest512_3(64, 0);
static bytes digest_shake_0(42, 0);
static bytes digest_shake_1(42, 0);
static bytes digest_shake_2(42, 0);
static bytes digest_shake_3(42, 0);

const size_t chunk_len = 135;

const bytes expected_digest_sha3_224 =
  from_hex("286c0137d80ed1fa81c06214ae451a665d554291aca2e5a6a48cf580");
const bytes expected_digest_sha3_256 =
  from_hex("7ac89d2c51ccf643bcaff3d747d79c0add61cbd46fb9439514e496154deae374");
const bytes expected_digest_sha3_384 =
  from_hex("7381e68f768394a730cdcbc9945aa8d8c701357605d48349545771f81ea94244c49"
           "61c8a4ff6b5bfc4b98cafb31e645c");
const bytes expected_digest_sha3_512 =
  from_hex("826308628fabfe511ccd2db232f374737785144703735ad07ebf8e31c2247608a0f"
           "ac23c4decd9a5264411c58c0b1591d084c0004b1ec86829a12dff96354ab5");

static void
Hacl_Sha3_224(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_SHA3_sha3_224(
      digest224_0.data(), (uint8_t*)input.data(), input.size());
  }
  if (digest224_0 != expected_digest_sha3_224) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_224)->Setup(DoSetup);

static void
Hacl_Scalar_Sha3_224(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Scalar_sha3_224(
      input.size(), (uint8_t*)input.data(), digest224_0.data());
  }
  if (digest224_0 != expected_digest_sha3_224) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Scalar_Sha3_224)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
Hacl_Vec256_Sha3_224(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Vec256_sha3_224_vec256(input.size(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     digest224_0.data(),
                                     digest224_1.data(),
                                     digest224_2.data(),
                                     digest224_3.data());
  }
  if (digest224_0 != expected_digest_sha3_224 ||
      digest224_1 != expected_digest_sha3_224 ||
      digest224_2 != expected_digest_sha3_224 ||
      digest224_3 != expected_digest_sha3_224) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Vec256_Sha3_224)->Setup(DoSetup);
#endif

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_224,
                  EVP_sha3_224(),
                  input,
                  digest224_0.size(),
                  expected_digest_sha3_224)
  ->Setup(DoSetup);
#endif

static void
Hacl_Sha3_256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_SHA3_sha3_256(
      digest256_0.data(), (uint8_t*)input.data(), input.size());
  }
  if (digest256_0 != expected_digest_sha3_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_256)->Setup(DoSetup);

static void
Hacl_Scalar_Sha3_256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Scalar_sha3_256(
      input.size(), (uint8_t*)input.data(), digest256_0.data());
  }
  if (digest256_0 != expected_digest_sha3_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Scalar_Sha3_256)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
Hacl_Vec256_Sha3_256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Vec256_sha3_256_vec256(input.size(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     digest256_0.data(),
                                     digest256_1.data(),
                                     digest256_2.data(),
                                     digest256_3.data());
  }
  if (digest256_0 != expected_digest_sha3_256 ||
      digest256_1 != expected_digest_sha3_256 ||
      digest256_2 != expected_digest_sha3_256 ||
      digest256_3 != expected_digest_sha3_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Vec256_Sha3_256)->Setup(DoSetup);
#endif

#include "sha3.h"

static void
Digestif_sha3_256(benchmark::State& state)
{
  bytes digest(32, 0);

  for (auto _ : state) {

    sha3_ctx ctx;
    digestif_sha3_init(&ctx, 256);

    for (auto chunk : chunk(input, chunk_len)) {
      digestif_sha3_update(&ctx, chunk.data(), chunk.size());
    }

    digestif_sha3_finalize(&ctx, digest.data(), 0x06);
  }

  if (digest != expected_digest_sha3_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Digestif_sha3_256)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_256,
                  EVP_sha3_256(),
                  input,
                  digest256_0.size(),
                  expected_digest_sha3_256)
  ->Setup(DoSetup);
#endif

static void
Hacl_Sha3_384(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_SHA3_sha3_384(
      digest384_0.data(), (uint8_t*)input.data(), input.size());
  }
  if (digest384_0 != expected_digest_sha3_384) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_384)->Setup(DoSetup);

static void
Hacl_Scalar_Sha3_384(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Scalar_sha3_384(
      input.size(), (uint8_t*)input.data(), digest384_0.data());
  }
  if (digest384_0 != expected_digest_sha3_384) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Scalar_Sha3_384)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC384
static void
Hacl_Vec384_Sha3_384(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Vec256_sha3_384_vec256(input.size(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     digest384_0.data(),
                                     digest384_1.data(),
                                     digest384_2.data(),
                                     digest384_3.data());
  }
  if (digest384_0 != expected_digest_sha3_384 ||
      digest384_1 != expected_digest_sha3_384 ||
      digest384_2 != expected_digest_sha3_384 ||
      digest384_3 != expected_digest_sha3_384) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Vec384_Sha3_384)->Setup(DoSetup);
#endif

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_384,
                  EVP_sha3_384(),
                  input,
                  digest384_0.size(),
                  expected_digest_sha3_384)
  ->Setup(DoSetup);
#endif

static void
Hacl_Sha3_512(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_SHA3_sha3_512(
      digest512_0.data(), (uint8_t*)input.data(), input.size());
  }
  if (digest512_0 != expected_digest_sha3_512) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_512)->Setup(DoSetup);

static void
Hacl_Scalar_Sha3_512(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Scalar_sha3_512(
      input.size(), (uint8_t*)input.data(), digest512_0.data());
  }
  if (digest512_0 != expected_digest_sha3_512) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Scalar_Sha3_512)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
Hacl_Vec512_Sha3_512(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Vec256_sha3_512_vec256(input.size(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     digest512_0.data(),
                                     digest512_1.data(),
                                     digest512_2.data(),
                                     digest512_3.data());
  }
  if (digest512_0 != expected_digest_sha3_512 ||
      digest512_1 != expected_digest_sha3_512 ||
      digest512_2 != expected_digest_sha3_512 ||
      digest512_3 != expected_digest_sha3_512) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Vec512_Sha3_512)->Setup(DoSetup);
#endif

static void
Digestif_sha3_512(benchmark::State& state)
{
  bytes digest(64, 0);

  for (auto _ : state) {

    sha3_ctx ctx;
    digestif_sha3_init(&ctx, 512);

    for (auto chunk : chunk(input, chunk_len)) {
      digestif_sha3_update(&ctx, chunk.data(), chunk.size());
    }

    digestif_sha3_finalize(&ctx, digest.data(), 0x06);
  }

  if (digest != expected_digest_sha3_512) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Digestif_sha3_512)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_512,
                  EVP_sha3_512(),
                  input,
                  digest512_0.size(),
                  expected_digest_sha3_512)
  ->Setup(DoSetup);
#endif

static void
Hacl_Sha3_256_Streaming(benchmark::State& state)
{
  for (auto _ : state) {
    // Init
    Hacl_Hash_SHA3_state_t* sha_state =
      Hacl_Hash_SHA3_malloc(Spec_Hash_Definitions_SHA3_256);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Hash_SHA3_update(sha_state,
                            (uint8_t*)input.data() + i,
                            min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Hash_SHA3_digest(sha_state, digest256_0.data());
    Hacl_Hash_SHA3_free(sha_state);
  }

  if (digest256_0 != expected_digest_sha3_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_256_Streaming)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_224,
                  EVP_sha3_224(),
                  input,
                  chunk_len,
                  digest224_0.size(),
                  expected_digest_sha3_224)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_256,
                  EVP_sha3_256(),
                  input,
                  chunk_len,
                  digest256_0.size(),
                  expected_digest_sha3_256)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_384,
                  EVP_sha3_384(),
                  input,
                  chunk_len,
                  digest384_0.size(),
                  expected_digest_sha3_384)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_512,
                  EVP_sha3_512(),
                  input,
                  chunk_len,
                  digest512_0.size(),
                  expected_digest_sha3_512)
  ->Setup(DoSetup);
#endif

static void
Hacl_Sha3_shake128(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_SHA3_shake128_hacl(input.size(),
                                 (uint8_t*)input.data(),
                                 digest_shake_0.size(),
                                 digest_shake_0.data());
  }
}

BENCHMARK(Hacl_Sha3_shake128)->Setup(DoSetup);

static void
Hacl_Scalar_Sha3_shake128(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Scalar_shake128_hacl(input.size(),
                                   (uint8_t*)input.data(),
                                   digest_shake_0.size(),
                                   digest_shake_0.data());
  }
}

BENCHMARK(Hacl_Scalar_Sha3_shake128)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
Hacl_Vec256_Sha3_shake128(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Vec256_shake128_vec256(input.size(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     digest_shake_0.size(),
                                     digest_shake_0.data(),
                                     digest_shake_1.data(),
                                     digest_shake_2.data(),
                                     digest_shake_3.data());
  }
}

BENCHMARK(Hacl_Vec256_Sha3_shake128)->Setup(DoSetup);
#endif

static void
Hacl_Sha3_shake256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_Hash_SHA3_shake256_hacl(input.size(),
                                 (uint8_t*)input.data(),
                                 digest_shake_0.size(),
                                 digest_shake_0.data());
  }
}

BENCHMARK(Hacl_Sha3_shake256)->Setup(DoSetup);

static void
Hacl_Scalar_Sha3_shake256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Scalar_shake256_hacl(input.size(),
                                   (uint8_t*)input.data(),
                                   digest_shake_0.size(),
                                   digest_shake_0.data());
  }
}

BENCHMARK(Hacl_Scalar_Sha3_shake256)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
Hacl_Vec256_Sha3_shake256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_Vec256_shake256_vec256(input.size(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     (uint8_t*)input.data(),
                                     digest_shake_0.size(),
                                     digest_shake_0.data(),
                                     digest_shake_1.data(),
                                     digest_shake_2.data(),
                                     digest_shake_3.data());
  }
}

BENCHMARK(Hacl_Vec256_Sha3_shake256)->Setup(DoSetup);
#endif

BENCHMARK_MAIN();
