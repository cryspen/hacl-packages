#include "util.h"

#include "Hacl_Hash_SHA1.h"

#define HACL_HASH_SHA1_DIGEST_LENGTH 20

static bytes input(1000, 0xAB);
static bytes digest(HACL_HASH_SHA1_DIGEST_LENGTH, 0);
static bytes expected_digest =
  from_hex("61dc7e8462a5113182fb2aa231dca0ae498c068b");
size_t chunk_len = 135;

static void
HACL_Sha1_oneshot(benchmark::State& state)
{
  bytes digest(HACL_HASH_SHA1_DIGEST_LENGTH, 0);

  for (auto _ : state) {
    Hacl_Streaming_SHA1_legacy_hash(input.data(), input.size(), digest.data());
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect SHA-1 digest.");
  }
}

BENCHMARK(HACL_Sha1_oneshot)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_Sha1_oneshot(benchmark::State& state)
{
  bytes digest(HACL_HASH_SHA1_DIGEST_LENGTH, 0);
  unsigned int len = digest.size();

  for (auto _ : state) {
    EVP_Digest(
      input.data(), input.size(), digest.data(), &len, EVP_sha1(), NULL);
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect SHA-1 digest.");
  }
}

BENCHMARK(OpenSSL_Sha1_oneshot)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_Sha1_streaming(benchmark::State& state)
{
  bytes digest(HACL_HASH_SHA1_DIGEST_LENGTH, 0);

  for (auto _ : state) {
    // Init
    Hacl_Streaming_SHA1_state* state =
      Hacl_Streaming_SHA1_legacy_create_in();
    Hacl_Streaming_SHA1_legacy_init(state);

    // Update
    for (size_t i = 0; i < input.size();) {
      Hacl_Streaming_SHA1_legacy_update(
        state, input.data() + i, min(chunk_len, input.size() - i));
      i += chunk_len;
    }

    // Finish
    Hacl_Streaming_SHA1_legacy_finish(state, digest.data());
    Hacl_Streaming_SHA1_legacy_free(state);
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect SHA-1 digest.");
  }
}

BENCHMARK(HACL_Sha1_streaming)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_Sha1_streaming(benchmark::State& state)
{
  bytes digest(HACL_HASH_SHA1_DIGEST_LENGTH, 0);

  for (auto _ : state) {
    // Init
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha1());

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      EVP_DigestUpdate(ctx, chunk.data(), chunk.size());
    }

    // Finish
    unsigned int len = digest.size();
    EVP_DigestFinal_ex(ctx, digest.data(), &len);
    EVP_MD_CTX_free(ctx);
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect SHA-1 digest.");
  }
}

BENCHMARK(OpenSSL_Sha1_streaming)->Setup(DoSetup);
#endif

BENCHMARK_MAIN();
