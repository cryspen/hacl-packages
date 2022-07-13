/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */
#include <benchmark/benchmark.h>

#include "hacl-cpu-features.h"

#include "Hacl_Chacha20.h"
#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Chacha20_Vec128.h"
#endif

const int INPUT_LEN = 1000;

static std::vector<uint8_t> plaintext(INPUT_LEN, 3);
static std::vector<uint8_t> key(32, 7);
static std::vector<uint8_t> nonce(12, 9);
static std::vector<uint8_t> ciphertext(INPUT_LEN, 0);

// Chacha non-vectorized
static void
BM_Chacha20_32_encrypt(benchmark::State& state)
{
  // TODO : generate random inputs

  for (auto _ : state) {
    Hacl_Chacha20_chacha20_encrypt(INPUT_LEN,
                                   ciphertext.data(),
                                   plaintext.data(),
                                   key.data(),
                                   nonce.data(),
                                   0);
  }
}
BENCHMARK(BM_Chacha20_32_encrypt);

// Chacha Vec128
static void
BM_Chacha20_Vec128_encrypt(benchmark::State& state)
{
  // TODO : generate random inputs

  for (auto _ : state) {
    Hacl_Chacha20_Vec128_chacha20_encrypt_128(INPUT_LEN,
                                              ciphertext.data(),
                                              plaintext.data(),
                                              key.data(),
                                              nonce.data(),
                                              0);
  }
}
BENCHMARK(BM_Chacha20_Vec128_encrypt);

// TODO: Vec256
// TODO: decrypt (even though it should be the same we should measure it)

BENCHMARK_MAIN();
