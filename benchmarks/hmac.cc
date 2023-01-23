/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "Hacl_HMAC.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_HMAC_Blake2b_256.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_HMAC_Blake2s_128.h"
#endif

#include "util.h"

#define HACL_MAC_HMAC_BLAKE2B_KEY_LEN_MAX 128
#define HACL_MAC_HMAC_BLAKE2S_KEY_LEN_MAX 64
#define HACL_MAC_HMAC_SHA2_256_KEY_LEN_MAX 64
#define HACL_MAC_HMAC_SHA2_384_KEY_LEN_MAX 128
#define HACL_MAC_HMAC_SHA2_512_KEY_LEN_MAX 128
#define HACL_MAC_HMAC_SHA1_KEY_LEN_MAX 64

#define HACL_MAC_HMAC_BLAKE2B_TAG_LEN 64
#define HACL_MAC_HMAC_BLAKE2S_TAG_LEN 32
#define HACL_MAC_HMAC_SHA2_256_TAG_LEN 32
#define HACL_MAC_HMAC_SHA2_384_TAG_LEN 48
#define HACL_MAC_HMAC_SHA2_512_TAG_LEN 64
#define HACL_MAC_HMAC_SHA1_TAG_LEN 20

static bytes msg = from_hex("CAFECAFECAFE");

// ----- BLAKE2b ---------------------------------------------------------------

static void
Hmac_Blake2b(benchmark::State& state)
{
  bytes key =
    from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
             "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743");
  bytes dst(HACL_MAC_HMAC_BLAKE2B_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_compute_blake2b_32(dst.data(),
                                 key.data(),
                                 HACL_MAC_HMAC_BLAKE2B_KEY_LEN_MAX,
                                 msg.data(),
                                 msg.size());
  }
}

BENCHMARK(Hmac_Blake2b);

#ifdef HACL_CAN_COMPILE_VEC256
static void
Hmac_Blake2b_Vec256(benchmark::State& state)
{
  cpu_init();
  if (!vec256_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  bytes key =
    from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
             "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743");
  bytes dst(HACL_MAC_HMAC_BLAKE2B_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_Blake2b_256_compute_blake2b_256(dst.data(),
                                              key.data(),
                                              HACL_MAC_HMAC_BLAKE2B_KEY_LEN_MAX,
                                              msg.data(),
                                              msg.size());
  }
}

BENCHMARK(Hmac_Blake2b_Vec256);
#endif

// ----- BLAKE2s ---------------------------------------------------------------

static void
Hmac_Blake2s(benchmark::State& state)
{
  bytes key = from_hex(
    "7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428");
  bytes dst(HACL_MAC_HMAC_BLAKE2S_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_compute_blake2s_32(dst.data(),
                                 key.data(),
                                 HACL_MAC_HMAC_BLAKE2S_KEY_LEN_MAX,
                                 msg.data(),
                                 msg.size());
  }
}

BENCHMARK(Hmac_Blake2s);

#ifdef HACL_CAN_COMPILE_VEC128
static void
Hmac_Blake2s_Vec128(benchmark::State& state)
{
  cpu_init();
  if (!vec128_support()) {
    state.SkipWithError("No vec128 support");
    return;
  }

  bytes key = from_hex(
    "7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428");
  bytes dst(HACL_MAC_HMAC_BLAKE2S_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_Blake2s_128_compute_blake2s_128(dst.data(),
                                              key.data(),
                                              HACL_MAC_HMAC_BLAKE2S_KEY_LEN_MAX,
                                              msg.data(),
                                              msg.size());
  }
}

BENCHMARK(Hmac_Blake2s_Vec128);
#endif

// ----- SHA-2-256
// ---------------------------------------------------------------

static void
Hmac_Sha2_256(benchmark::State& state)
{
  bytes key = from_hex(
    "7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428");
  bytes dst(HACL_MAC_HMAC_SHA2_256_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_compute_sha2_256(dst.data(),
                               key.data(),
                               HACL_MAC_HMAC_SHA2_256_KEY_LEN_MAX,
                               msg.data(),
                               msg.size());
  }
}

BENCHMARK(Hmac_Sha2_256);

// ----- SHA-2-384
// ---------------------------------------------------------------

static void
Hmac_Sha2_384(benchmark::State& state)
{
  bytes key =
    from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
             "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743");
  bytes dst(HACL_MAC_HMAC_SHA2_384_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_compute_sha2_384(dst.data(),
                               key.data(),
                               HACL_MAC_HMAC_SHA2_384_KEY_LEN_MAX,
                               msg.data(),
                               msg.size());
  }
}

BENCHMARK(Hmac_Sha2_384);

// ----- SHA-2-512
// ---------------------------------------------------------------

static void
Hmac_Sha2_512(benchmark::State& state)
{
  bytes key =
    from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
             "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743");
  bytes dst(HACL_MAC_HMAC_SHA2_512_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_compute_sha2_512(dst.data(),
                               key.data(),
                               HACL_MAC_HMAC_SHA2_512_KEY_LEN_MAX,
                               msg.data(),
                               msg.size());
  }
}

BENCHMARK(Hmac_Sha2_512);

// ----- SHA-1 ---------------------------------------------------------------

static void
Hmac_Sha1(benchmark::State& state)
{
  bytes key = from_hex(
    "7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428");
  bytes dst(HACL_MAC_HMAC_SHA1_TAG_LEN);

  for (auto _ : state) {
    Hacl_HMAC_legacy_compute_sha1(dst.data(),
                                  key.data(),
                                  HACL_MAC_HMAC_SHA1_KEY_LEN_MAX,
                                  msg.data(),
                                  msg.size());
  }
}

BENCHMARK(Hmac_Sha1);

BENCHMARK_MAIN();
