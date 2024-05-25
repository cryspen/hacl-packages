/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "libcrux_ml_kem.h"
#include "util.h"

static void
kyber768_key_generation(benchmark::State& state)
{
  uint8_t randomness[64];
  generate_random(randomness, 64);
  auto key_pair = libcrux_ml_kem_mlkem768_generate_key_pair(randomness);  

  for (auto _ : state) { 
    key_pair = libcrux_ml_kem_mlkem768_generate_key_pair(randomness);  
   }
}

static void
kyber768_encapsulation(benchmark::State& state)
{
  uint8_t randomness[64];
  generate_random(randomness, 64);

  auto key_pair = libcrux_ml_kem_mlkem768_generate_key_pair(randomness);
  generate_random(randomness, 32);
  auto ctxt = libcrux_ml_kem_mlkem768_encapsulate(&key_pair.pk, randomness);

  for (auto _ : state) {
    ctxt = libcrux_ml_kem_mlkem768_encapsulate(&key_pair.pk, randomness);
  }
}

static void
kyber768_decapsulation(benchmark::State& state)
{
  uint8_t randomness[64];
  generate_random(randomness, 64);

  auto key_pair = libcrux_ml_kem_mlkem768_generate_key_pair(randomness);
  generate_random(randomness, 32);
  auto ctxt = libcrux_ml_kem_mlkem768_encapsulate(&key_pair.pk, randomness);

  uint8_t sharedSecret2[LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_SIZE];

  for (auto _ : state) {
    libcrux_ml_kem_mlkem768_decapsulate(&key_pair.sk, &ctxt.fst, sharedSecret2);
  }
}

BENCHMARK(kyber768_key_generation)->Setup(DoSetup);
BENCHMARK(kyber768_encapsulation)->Setup(DoSetup);
BENCHMARK(kyber768_decapsulation)->Setup(DoSetup);

BENCHMARK_MAIN();
