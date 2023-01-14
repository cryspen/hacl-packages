/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "Hacl_HMAC_DRBG.h"

#include "util.h"

static bytes entropy_input = from_hex("98AD3A7FE9E908452A633AA3B9E46E7E324766");
static bytes nonce = from_hex("6DF336AB15C2BED6AC6FC793705EBBAAFE");
static bytes personalization_string =
  from_hex("AF65C375F0850AF29CC3FE6C0C1D31F4");
static bytes additional_input = from_hex("1CA8F61C");
static bytes output(128);

inline void
Drbg_complete(benchmark::State& state, Spec_Hash_Definitions_hash_alg algorithm)
{
  for (auto _ : state) {
    Hacl_HMAC_DRBG_state state = Hacl_HMAC_DRBG_create_in(algorithm);
    Hacl_HMAC_DRBG_instantiate(algorithm,
                               state,
                               entropy_input.size(),
                               entropy_input.data(),
                               nonce.size(),
                               nonce.data(),
                               personalization_string.size(),
                               personalization_string.data());

    Hacl_HMAC_DRBG_generate(algorithm,
                            output.data(),
                            state,
                            output.size(),
                            additional_input.size(),
                            additional_input.data());

    Hacl_HMAC_DRBG_free(Spec_Hash_Definitions_SHA2_256, state);
  }
}

// ----- SHA-2 256 -------------------------------------------------------------

static void Drbg_SHA2_256_complete(benchmark::State& state)
{
  Drbg_complete(state, Spec_Hash_Definitions_SHA2_256);
}

BENCHMARK(Drbg_SHA2_256_complete);

// ----- SHA-2 384 -------------------------------------------------------------

static void Drbg_SHA2_384_complete(benchmark::State& state)
{
  Drbg_complete(state, Spec_Hash_Definitions_SHA2_384);
}

BENCHMARK(Drbg_SHA2_384_complete);

// ----- SHA-2 512 -------------------------------------------------------------

static void Drbg_SHA2_512_complete(benchmark::State& state)
{
  Drbg_complete(state, Spec_Hash_Definitions_SHA2_512);
}

BENCHMARK(Drbg_SHA2_512_complete);

// ----- SHA-1 -----------------------------------------------------------------

static void Drbg_SHA1_complete(benchmark::State& state)
{
  Drbg_complete(state, Spec_Hash_Definitions_SHA1);
}

BENCHMARK(Drbg_SHA1_complete);

BENCHMARK_MAIN();
