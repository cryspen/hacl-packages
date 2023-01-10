#include "util.h"

#include "Hacl_SHA3.h"

#include "Hacl_Streaming_SHA3.h"

static bytes input(1000, 0x37);
static bytes digest224(28, 0);
static bytes digest256(32, 0);
static bytes digest384(48, 0);
static bytes digest512(64, 0);
static bytes digest_shake(42, 0);

static void
Hacl_Sha3_224(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_SHA3_sha3_224(input.size(), input.data(), digest224.data());
  }
}

BENCHMARK(Hacl_Sha3_224);

static void
Hacl_Sha3_256(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_SHA3_sha3_256(input.size(), input.data(), digest256.data());
  }
}

BENCHMARK(Hacl_Sha3_256);

static void
Hacl_Sha3_384(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_SHA3_sha3_384(input.size(), input.data(), digest384.data());
  }
}

BENCHMARK(Hacl_Sha3_384);

static void
Hacl_Sha3_512(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_SHA3_sha3_512(input.size(), input.data(), digest512.data());
  }
}

BENCHMARK(Hacl_Sha3_512);

static void
Hacl_Sha3_256_Streaming(benchmark::State& state)
{
  size_t chunk_len = 135;

  while (state.KeepRunning()) {
    // Init
    Hacl_Streaming_SHA2_state_sha2_384* sha_state =
      Hacl_Streaming_SHA3_create_in_256();
    Hacl_Streaming_SHA3_init_256(sha_state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA3_update_256(
        sha_state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA3_finish_256(sha_state, digest256.data());
    Hacl_Streaming_SHA3_free_256(sha_state);
  }
}

BENCHMARK(Hacl_Sha3_256_Streaming);

static void
Hacl_Sha3_shake128(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_SHA3_shake128_hacl(
      input.size(), input.data(), digest_shake.size(), digest_shake.data());
  }
}

BENCHMARK(Hacl_Sha3_shake128);

static void
Hacl_Sha3_shake256(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_SHA3_shake256_hacl(
      input.size(), input.data(), digest_shake.size(), digest_shake.data());
  }
}

BENCHMARK(Hacl_Sha3_shake256);

BENCHMARK_MAIN();
