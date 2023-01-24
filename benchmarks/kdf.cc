/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "EverCrypt_HKDF.h"
#include "Hacl_HKDF.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_HKDF_Blake2s_128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_HKDF_Blake2b_256.h"
#endif

#include "util.h"

#define HACL_KDF_HKDF_BLAKE2B_PRK_LEN 64
#define HACL_KDF_HKDF_BLAKE2S_PRK_LEN 32
#define HACL_KDF_HKDF_SHA2_256_PRK_LEN 32
#define HACL_KDF_HKDF_SHA2_512_PRK_LEN 64

static bytes ikm = from_hex("5e7027e9bc462ee334432f8e31d3b5b0"
                            "2abb486d123adeb9fea106f738d0b699"
                            "b5dc5636a2d7219c3efa58b7ca7b561c"
                            "c7621305856cae06c745a104992db0b9"
                            "07af0a795748e8d07020fc927a9b26b1"
                            "0f702b89b1d1546f17e2a1a83d2ee4bb"
                            "c03eff42507e5e37a17db36b30767cd1"
                            "ff21a15fe692ef89b34bba78a48d6d91"
                            "5c708c51e932909597c85f329f10358e"
                            "fac855a4bbdf882844df201a4ea9772b"
                            "5f29d4cb858b67b96177eece58aaada1"
                            "075164399011466612226c8fe6f0916b"
                            "158adde1e017ec366ddb4459d1c5c8b0"
                            "58f0f24240a34f6a176c5df2e45b97a6"
                            "930cda8a3f7314d1ead6b6871a9bb8a6"
                            "42135d0deb9cf5dab3e35c4d1ab0a42b");
static bytes salt = from_hex("90777c9b9313072d7859c12782dc415b");
static bytes okm(128);
static bytes info = from_hex("431ae40d230f8ea6b59704ff363f9d3e");

static void
HACL_HKDF_BLAKE2b_32_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_BLAKE2B_PRK_LEN];

  for (auto _ : state) {
    Hacl_HKDF_extract_blake2b_32(
      prk, (uint8_t*)salt.data(), salt.size(), ikm.data(), ikm.size());
    Hacl_HKDF_expand_blake2b_32(okm.data(),
                                prk,
                                HACL_KDF_HKDF_BLAKE2B_PRK_LEN,
                                info.data(),
                                info.size(),
                                okm.size());
  }
}

BENCHMARK(HACL_HKDF_BLAKE2b_32_extract_expand)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC256
static void
HACL_HKDF_BLAKE2b_Vec256_extract_expand(benchmark::State& state)
{
  if (!vec256_support()) {
    state.SkipWithError("No VEC256 support.");
    return;
  }

  uint8_t prk[HACL_KDF_HKDF_BLAKE2B_PRK_LEN];

  for (auto _ : state) {
    Hacl_HKDF_Blake2b_256_extract_blake2b_256(
      prk, (uint8_t*)salt.data(), salt.size(), ikm.data(), ikm.size());
    Hacl_HKDF_Blake2b_256_expand_blake2b_256(okm.data(),
                                             prk,
                                             HACL_KDF_HKDF_BLAKE2B_PRK_LEN,
                                             info.data(),
                                             info.size(),
                                             okm.size());
  }
}

BENCHMARK(HACL_HKDF_BLAKE2b_Vec256_extract_expand)->Setup(DoSetup);
#endif

static void
EverCrypt_HKDF_BLAKE2b_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_BLAKE2B_PRK_LEN];

  for (auto _ : state) {
    EverCrypt_HKDF_extract(Spec_Hash_Definitions_Blake2B,
                           prk,
                           salt.data(),
                           salt.size(),
                           ikm.data(),
                           ikm.size());
    EverCrypt_HKDF_expand(Spec_Hash_Definitions_Blake2B,
                          okm.data(),
                          prk,
                          HACL_KDF_HKDF_BLAKE2B_PRK_LEN,
                          info.data(),
                          info.size(),
                          okm.size());
  }
}

BENCHMARK(EverCrypt_HKDF_BLAKE2b_extract_expand)->Setup(DoSetup);

static void
HACL_HKDF_BLAKE2s_32_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_BLAKE2S_PRK_LEN];

  for (auto _ : state) {
    Hacl_HKDF_extract_blake2s_32(
      prk, (uint8_t*)salt.data(), salt.size(), ikm.data(), ikm.size());
    Hacl_HKDF_expand_blake2s_32(okm.data(),
                                prk,
                                HACL_KDF_HKDF_BLAKE2S_PRK_LEN,
                                info.data(),
                                info.size(),
                                okm.size());
  }
}

BENCHMARK(HACL_HKDF_BLAKE2s_32_extract_expand)->Setup(DoSetup);

#ifdef HACL_CAN_COMPILE_VEC128
static void
HACL_HKDF_BLAKE2s_Vec128_extract_expand(benchmark::State& state)
{
  if (!vec128_support()) {
    state.SkipWithError("No VEC128 support.");
    return;
  }

  uint8_t prk[HACL_KDF_HKDF_BLAKE2S_PRK_LEN];

  for (auto _ : state) {
    Hacl_HKDF_Blake2s_128_extract_blake2s_128(
      prk, (uint8_t*)salt.data(), salt.size(), ikm.data(), ikm.size());
    Hacl_HKDF_Blake2s_128_expand_blake2s_128(okm.data(),
                                             prk,
                                             HACL_KDF_HKDF_BLAKE2S_PRK_LEN,
                                             info.data(),
                                             info.size(),
                                             okm.size());
  }
}

BENCHMARK(HACL_HKDF_BLAKE2s_Vec128_extract_expand)->Setup(DoSetup);
#endif

static void
EverCrypt_HKDF_BLAKE2s_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_BLAKE2S_PRK_LEN];

  for (auto _ : state) {
    EverCrypt_HKDF_extract(Spec_Hash_Definitions_Blake2S,
                           prk,
                           salt.data(),
                           salt.size(),
                           ikm.data(),
                           ikm.size());
    EverCrypt_HKDF_expand(Spec_Hash_Definitions_Blake2S,
                          okm.data(),
                          prk,
                          HACL_KDF_HKDF_BLAKE2S_PRK_LEN,
                          info.data(),
                          info.size(),
                          okm.size());
  }
}

BENCHMARK(EverCrypt_HKDF_BLAKE2s_extract_expand)->Setup(DoSetup);

static void
HACL_HKDF_SHA2_256_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_SHA2_256_PRK_LEN];

  for (auto _ : state) {
    Hacl_HKDF_extract_sha2_256(
      prk, (uint8_t*)salt.data(), salt.size(), ikm.data(), ikm.size());
    Hacl_HKDF_expand_sha2_256(okm.data(),
                              prk,
                              HACL_KDF_HKDF_SHA2_256_PRK_LEN,
                              info.data(),
                              info.size(),
                              okm.size());
  }
}

BENCHMARK(HACL_HKDF_SHA2_256_extract_expand)->Setup(DoSetup);

static void
EverCrypt_HKDF_SHA2_256_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_SHA2_256_PRK_LEN];

  for (auto _ : state) {
    EverCrypt_HKDF_extract(Spec_Hash_Definitions_SHA2_256,
                           prk,
                           salt.data(),
                           salt.size(),
                           ikm.data(),
                           ikm.size());
    EverCrypt_HKDF_expand(Spec_Hash_Definitions_SHA2_256,
                          okm.data(),
                          prk,
                          HACL_KDF_HKDF_SHA2_256_PRK_LEN,
                          info.data(),
                          info.size(),
                          okm.size());
  }
}

BENCHMARK(EverCrypt_HKDF_SHA2_256_extract_expand)->Setup(DoSetup);

static void
HACL_HKDF_SHA2_512_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_SHA2_512_PRK_LEN];

  for (auto _ : state) {
    Hacl_HKDF_extract_sha2_512(
      prk, (uint8_t*)salt.data(), salt.size(), ikm.data(), ikm.size());
    Hacl_HKDF_expand_sha2_512(okm.data(),
                              prk,
                              HACL_KDF_HKDF_SHA2_512_PRK_LEN,
                              info.data(),
                              info.size(),
                              okm.size());
  }
}

BENCHMARK(HACL_HKDF_SHA2_512_extract_expand)->Setup(DoSetup);

static void
EverCrypt_HKDF_SHA2_512_extract_expand(benchmark::State& state)
{
  uint8_t prk[HACL_KDF_HKDF_SHA2_512_PRK_LEN];

  for (auto _ : state) {
    EverCrypt_HKDF_extract(Spec_Hash_Definitions_SHA2_512,
                           prk,
                           salt.data(),
                           salt.size(),
                           ikm.data(),
                           ikm.size());
    EverCrypt_HKDF_expand(Spec_Hash_Definitions_SHA2_512,
                          okm.data(),
                          prk,
                          HACL_KDF_HKDF_SHA2_512_PRK_LEN,
                          info.data(),
                          info.size(),
                          okm.size());
  }
}

BENCHMARK(EverCrypt_HKDF_SHA2_512_extract_expand)->Setup(DoSetup);

BENCHMARK_MAIN();
