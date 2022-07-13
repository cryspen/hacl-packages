/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */
#include <benchmark/benchmark.h>

#include "hacl-cpu-features.h"

#include "Hacl_Hash_Blake2.h"
#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#endif

const int INPUT_LEN = 1000;

static std::vector<uint8_t> input(INPUT_LEN);
static std::vector<uint8_t> key(64);
static std::vector<uint8_t> digest(64, 0);

// Blake2b 32-bit
static void
BM_Blake2b_32(benchmark::State& state)
{
  // TODO : generate random inputs

  for (auto _ : state) {
    Hacl_Blake2b_32_blake2b(input.size(),
                            input.data(),
                            key.size(),
                            key.data(),
                            digest.size(),
                            digest.data());
  }
}
BENCHMARK(BM_Blake2b_32);

// Blake2s 32-bit
static void
BM_Blake2s_32(benchmark::State& state)
{
  // TODO : generate random inputs

  for (auto _ : state) {
    Hacl_Blake2s_32_blake2s(digest.size(),
                            digest.data(),
                            input.size(),
                            input.data(),
                            key.size(),
                            key.data());
  }
}
BENCHMARK(BM_Blake2s_32);

// Blake2s vec128
static void
BM_Blake2s_vec128(benchmark::State& state)
{
  // TODO : generate random inputs

  for (auto _ : state) {
    Hacl_Blake2s_128_blake2s(digest.size(),
                             digest.data(),
                             input.size(),
                             input.data(),
                             key.size(),
                             key.data());
  }
}
BENCHMARK(BM_Blake2s_vec128);

BENCHMARK_MAIN();
