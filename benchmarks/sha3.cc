#include "util.h"

#include "Hacl_Hash_SHA3.h"

const bytes input(1000, 0x37);

static bytes digest224(28, 0);
static bytes digest256(32, 0);
static bytes digest384(48, 0);
static bytes digest512(64, 0);
static bytes digest_shake(42, 0);

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
    Hacl_SHA3_sha3_224(input.size(), (uint8_t*)input.data(), digest224.data());
  }
  if (digest224 != expected_digest_sha3_224) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_224)->Setup(DoSetup);

static void
Hacl_Sha3_256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_sha3_256(input.size(), (uint8_t*)input.data(), digest256.data());
  }
  if (digest256 != expected_digest_sha3_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_256)->Setup(DoSetup);

static void
Hacl_Sha3_384(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_sha3_384(input.size(), (uint8_t*)input.data(), digest384.data());
  }
  if (digest384 != expected_digest_sha3_384) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_384)->Setup(DoSetup);

static void
Hacl_Sha3_512(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_sha3_512(input.size(), (uint8_t*)input.data(), digest512.data());
  }
  if (digest512 != expected_digest_sha3_512) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_512)->Setup(DoSetup);

static void
Hacl_Sha3_256_Streaming(benchmark::State& state)
{
  for (auto _ : state) {
    // Init
    Hacl_Streaming_SHA3_state_256* sha_state =
      Hacl_Streaming_SHA3_create_in_256();
    Hacl_Streaming_SHA3_init_256(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA3_update_256(sha_state,
                                     (uint8_t*)input.data() + i,
                                     min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA3_finish_256(sha_state, digest256.data());
    Hacl_Streaming_SHA3_free_256(sha_state);
  }

  if (digest256 != expected_digest_sha3_256) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}

BENCHMARK(Hacl_Sha3_256_Streaming)->Setup(DoSetup);

static void
Hacl_Sha3_shake128(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_shake128_hacl(input.size(),
                            (uint8_t*)input.data(),
                            digest_shake.size(),
                            digest_shake.data());
  }
}

BENCHMARK(Hacl_Sha3_shake128)->Setup(DoSetup);

static void
Hacl_Sha3_shake256(benchmark::State& state)
{
  for (auto _ : state) {
    Hacl_SHA3_shake256_hacl(input.size(),
                            (uint8_t*)input.data(),
                            digest_shake.size(),
                            digest_shake.data());
  }
}

BENCHMARK(Hacl_Sha3_shake256)->Setup(DoSetup);

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_224,
                  EVP_sha3_224(),
                  input,
                  digest224.size(),
                  expected_digest_sha3_224)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_256,
                  EVP_sha3_256(),
                  input,
                  digest256.size(),
                  expected_digest_sha3_256)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_384,
                  EVP_sha3_384(),
                  input,
                  digest384.size(),
                  expected_digest_sha3_384)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_512,
                  EVP_sha3_512(),
                  input,
                  digest512.size(),
                  expected_digest_sha3_512)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_224,
                  EVP_sha3_224(),
                  input,
                  chunk_len,
                  digest224.size(),
                  expected_digest_sha3_224)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_256,
                  EVP_sha3_256(),
                  input,
                  chunk_len,
                  digest256.size(),
                  expected_digest_sha3_256)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_384,
                  EVP_sha3_384(),
                  input,
                  chunk_len,
                  digest384.size(),
                  expected_digest_sha3_384)
  ->Setup(DoSetup);

BENCHMARK_CAPTURE(OpenSSL_hash_streaming,
                  sha3_512,
                  EVP_sha3_512(),
                  input,
                  chunk_len,
                  digest512.size(),
                  expected_digest_sha3_512)
  ->Setup(DoSetup);
#endif

BENCHMARK_MAIN();
