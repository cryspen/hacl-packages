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

template<class... Args>
void
HACL_Drbg_complete(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);
  Spec_Hash_Definitions_hash_alg algorithm = std::get<0>(args_tuple);

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

    Hacl_HMAC_DRBG_free(algorithm, state);
  }
}

BENCHMARK_CAPTURE(HACL_Drbg_complete, sha2_256, Spec_Hash_Definitions_SHA2_256)
  ->Setup(DoSetup);
BENCHMARK_CAPTURE(HACL_Drbg_complete, sha2_384, Spec_Hash_Definitions_SHA2_384)
  ->Setup(DoSetup);
BENCHMARK_CAPTURE(HACL_Drbg_complete, sha2_512, Spec_Hash_Definitions_SHA2_512)
  ->Setup(DoSetup);
BENCHMARK_CAPTURE(HACL_Drbg_complete, sha1, Spec_Hash_Definitions_SHA1)
  ->Setup(DoSetup);

BENCHMARK_MAIN();
