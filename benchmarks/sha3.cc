#include "util.h"

#include "Hacl_Hash_SHA3.h"
#include "keccak.h"

const bytes input(34, 0x37);

static bytes digest224(28, 0);
static bytes digest256(32, 0);
static bytes digest384(48, 0);
static bytes digest512(64, 0);
static bytes digest_shake(840, 0);

const size_t chunk_len = 135;

const bytes expected_digest_sha3_224 =
  from_hex("350400f2c2590bca4b9d68573c66e1f01dec624217569d9e77d7d2d7");
const bytes expected_digest_sha3_256 =
  from_hex("1181ca1f5bf35d540704ac42cd17f642ccb2d7d30a94a747ba283cc496ffb6a9");
const bytes expected_digest_sha3_384 =
  from_hex("c155ca5e66ab9bc7f7ad181e386d23d1ecf6a8fb5073044e3e79dda29c3e76976e0"
           "ca1c75f2655868da764ec39646060");
const bytes expected_digest_sha3_512 =
  from_hex("e1120a1749593f20e4fb9d815221085f73224a89d6a53456eeee63b98c30a00d345"
           "5920ae9ee15b1fed68213949bdf4f82c47b5538c2aa2fa320731fae116a9d");

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

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_224,
                  EVP_sha3_224(),
                  input,
                  digest224.size(),
                  expected_digest_sha3_224)
  ->Setup(DoSetup);
#endif

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
                  digest256.size(),
                  expected_digest_sha3_256)
  ->Setup(DoSetup);
#endif

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

#ifndef NO_OPENSSL
BENCHMARK_CAPTURE(OpenSSL_hash_oneshot,
                  sha3_384,
                  EVP_sha3_384(),
                  input,
                  digest384.size(),
                  expected_digest_sha3_384)
  ->Setup(DoSetup);
#endif

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
                  digest512.size(),
                  expected_digest_sha3_512)
  ->Setup(DoSetup);
#endif

static void
Hacl_Sha3_256_Streaming(benchmark::State& state)
{
  for (auto _ : state) {
    // Init
    Hacl_Streaming_Keccak_state* sha_state =
      Hacl_Streaming_Keccak_malloc(Spec_Hash_Definitions_SHA3_256);
    Hacl_Streaming_Keccak_reset(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_Keccak_update(sha_state,
                                   (uint8_t*)input.data() + i,
                                   min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_Keccak_finish(sha_state, digest256.data());
    Hacl_Streaming_Keccak_free(sha_state);
  }

  if (digest256 != expected_digest_sha3_256) {
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

static void
Hacl_Sha3_shake128(benchmark::State& state)
{
  // Manual warmup
  for(size_t i = 0; i<200; i++) {
    Hacl_SHA3_shake128_hacl(input.size(),
                            (uint8_t*)input.data(),
                            digest_shake.size(),
                            digest_shake.data());
  }

  for (auto _ : state) {
    Hacl_SHA3_shake128_hacl(input.size(),
                            (uint8_t*)input.data(),
                            digest_shake.size(),
                            digest_shake.data());
  }
}

BENCHMARK(Hacl_Sha3_shake128)->Setup(DoSetup);

extern "C" void BORINGSSL_keccak(uint8_t *out, size_t out_len,
                                     const uint8_t *in, size_t in_len,
                                     enum boringssl_keccak_config_t config);

static void
BoringSSL_Sha3_shake128(benchmark::State& state)
{
  // Manual warmup
  for(size_t i = 0; i<200; i++) {
    BORINGSSL_keccak((uint8_t*)digest_shake.data(), (size_t)digest_shake.size(), 
                     (uint8_t*)input.data(), input.size(),
                     boringssl_shake128);
  }

  for (auto _ : state) {
    BORINGSSL_keccak((uint8_t*)digest_shake.data(), (size_t)digest_shake.size(), 
                     (uint8_t*)input.data(), input.size(),
                     boringssl_shake128);
  }
}

BENCHMARK(BoringSSL_Sha3_shake128)->Setup(DoSetup);

static void
Hacl_Sha3_shake256(benchmark::State& state)
{
  // Manual warmup
  for(size_t i = 0; i<200; i++) {
    Hacl_SHA3_shake256_hacl(input.size(),
                            (uint8_t*)input.data(),
                            digest_shake.size(),
                            digest_shake.data());
  }

  for (auto _ : state) {
    Hacl_SHA3_shake256_hacl(input.size(),
                            (uint8_t*)input.data(),
                            digest_shake.size(),
                            digest_shake.data());
  }
}

BENCHMARK(Hacl_Sha3_shake256)->Setup(DoSetup);

static void
BoringSSL_Sha3_shake256(benchmark::State& state)
{
  // Manual warmup
  for(size_t i = 0; i<200; i++) {
    BORINGSSL_keccak((uint8_t*)digest_shake.data(), (size_t)digest_shake.size(), 
                     (uint8_t*)input.data(), input.size(),
                     boringssl_shake256);
  }

  for (auto _ : state) {
    BORINGSSL_keccak((uint8_t*)digest_shake.data(), (size_t)digest_shake.size(), 
                     (uint8_t*)input.data(), input.size(),
                     boringssl_shake256);
  }
}

BENCHMARK(BoringSSL_Sha3_shake256)->Setup(DoSetup);

BENCHMARK_MAIN();
