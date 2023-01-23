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

#define HACL_MAC_HMAC_BLAKE2B_TAG_LEN 64
#define HACL_MAC_HMAC_BLAKE2S_TAG_LEN 32
#define HACL_MAC_HMAC_SHA2_256_TAG_LEN 32
#define HACL_MAC_HMAC_SHA2_384_TAG_LEN 48
#define HACL_MAC_HMAC_SHA2_512_TAG_LEN 64
#define HACL_MAC_HMAC_SHA1_TAG_LEN 20

template<class... Args>
void
HACL_Hmac(benchmark::State& state, Args&&... args)
{
  cpu_init();

#ifdef HACL_CAN_COMPILE_VEC128
  if (!vec128_support()) {
    state.SkipWithError("No Vec128 support");
    return;
  }
#endif

#ifdef HACL_CAN_COMPILE_VEC256
  if (!vec256_support()) {
    state.SkipWithError("No Vec256 support");
    return;
  }
#endif

  auto args_tuple = std::make_tuple(std::move(args)...);

  bytes msg(state.range(0), 0xAB);
  bytes key = std::get<0>(args_tuple);
  bytes dst(std::get<1>(args_tuple));
  auto hmac = std::get<2>(args_tuple);

  for (auto _ : state) {
    hmac(dst.data(), key.data(), key.size(), msg.data(), msg.size());
  }
}

static void
Range(benchmark::internal::Benchmark* b)
{
  b->Arg(0);
  for (size_t i = 16; i <= 16 * 1024 * 1024; i = i * 16) {
    b->Arg(i);
  }
}

BENCHMARK_CAPTURE(
  HACL_Hmac,
  blake2b,
  from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
           "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743"),
  HACL_MAC_HMAC_BLAKE2B_TAG_LEN,
  Hacl_HMAC_compute_blake2b_32)
  ->Apply(Range);

#ifdef HACL_CAN_COMPILE_VEC256
BENCHMARK_CAPTURE(
  HACL_Hmac,
  blake2b_vec256,
  from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
           "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743"),
  HACL_MAC_HMAC_BLAKE2B_TAG_LEN,
  Hacl_HMAC_Blake2b_256_compute_blake2b_256)
  ->Apply(Range);
#endif

BENCHMARK_CAPTURE(
  HACL_Hmac,
  blake2s,
  from_hex("7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428"),
  HACL_MAC_HMAC_BLAKE2S_TAG_LEN,
  Hacl_HMAC_compute_blake2s_32)
  ->Apply(Range);

#ifdef HACL_CAN_COMPILE_VEC128
BENCHMARK_CAPTURE(
  HACL_Hmac,
  blake2s_vec128,
  from_hex("7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428"),
  HACL_MAC_HMAC_BLAKE2S_TAG_LEN,
  Hacl_HMAC_Blake2s_128_compute_blake2s_128)
  ->Apply(Range);
#endif

BENCHMARK_CAPTURE(
  HACL_Hmac,
  sha2_256,
  from_hex("7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428"),
  HACL_MAC_HMAC_SHA2_256_TAG_LEN,
  Hacl_HMAC_compute_sha2_256)
  ->Arg(4096);

BENCHMARK_CAPTURE(
  HACL_Hmac,
  sha2_384,
  from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
           "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743"),
  HACL_MAC_HMAC_SHA2_384_TAG_LEN,
  Hacl_HMAC_compute_sha2_384)
  ->Arg(4096);

BENCHMARK_CAPTURE(
  HACL_Hmac,
  sha2_512,
  from_hex("A74714CF162F048E7917944F0EF221CC0BBB561D7D88B5D7CF48B02405C961372"
           "0435512805899EA7AE995C0F94014ECDFF710E008B029FA990AD57BCCBAE743"),
  HACL_MAC_HMAC_SHA2_512_TAG_LEN,
  Hacl_HMAC_compute_sha2_512)
  ->Arg(4096);

BENCHMARK_CAPTURE(
  HACL_Hmac,
  sha1,
  from_hex("7DD9CDC17DD7C7CD4B1D39C13FA7E511354CC6EB7F5BEB07ED2D353E138A9428"),
  HACL_MAC_HMAC_SHA1_TAG_LEN,
  Hacl_HMAC_legacy_compute_sha1)
  ->Arg(4096);

BENCHMARK_MAIN();
