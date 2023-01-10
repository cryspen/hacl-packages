#include "util.h"

#include "Hacl_Hash_SHA1.h"
#include "Hacl_Streaming_SHA1.h"

#define HACL_HASH_SHA1_DIGEST_LENGTH 20

static bytes input(1000, 0x37);
static bytes digest(HACL_HASH_SHA1_DIGEST_LENGTH, 0);

static void
Hacl_Sha1_oneshot(benchmark::State& state)
{
  while (state.KeepRunning()) {
    Hacl_Hash_SHA1_legacy_hash(input.data(), input.size(), digest.data());
  }
}

BENCHMARK(Hacl_Sha1_oneshot);

static void
Hacl_Sha1_streaming(benchmark::State& state)
{
  size_t chunk_len = 135;
  while (state.KeepRunning()) {
    // Init
    Hacl_Streaming_SHA1_state_sha1* state =
      Hacl_Streaming_SHA1_legacy_create_in_sha1();
    Hacl_Streaming_SHA1_legacy_init_sha1(state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA1_legacy_update_sha1(
        state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA1_legacy_finish_sha1(state, digest.data());
    Hacl_Streaming_SHA1_legacy_free_sha1(state);
  }
}

BENCHMARK(Hacl_Sha1_streaming);

BENCHMARK_MAIN();
