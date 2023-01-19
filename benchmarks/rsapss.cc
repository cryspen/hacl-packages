/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "Hacl_Hash_Base.h"
#include "Hacl_RSAPSS.h"

#include "util.h"

static bytes msg = from_hex("CAFECAFECAFECAFE");

static void
Rsapss_sign(benchmark::State& state)
{
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSAPSS_new_rsapss_load_skey(modBits, eBits, dBits, mod, e, d);

  uint32_t saltLen = Hacl_Hash_Definitions_hash_len(state.range(0));
  uint8_t* salt = (uint8_t*)malloc(saltLen);

  uint32_t sgntLen = modBits / 8;
  uint8_t* sgnt = (uint8_t*)malloc(sgntLen);

  for (auto _ : state) {
    Hacl_RSAPSS_rsapss_sign(state.range(0),
                            modBits,
                            eBits,
                            dBits,
                            skey,
                            saltLen,
                            salt,
                            msg.size(),
                            msg.data(),
                            sgnt);
  }

  free(sgnt);
  free(salt);
  free(skey);
  free(mod);
  free(d);
  free(e);
}

BENCHMARK(Rsapss_sign)
  ->Arg(Spec_Hash_Definitions_SHA2_256)
  ->Arg(Spec_Hash_Definitions_SHA2_384)
  ->Arg(Spec_Hash_Definitions_SHA2_512);

static void
Rsapss_verify(benchmark::State& state)
{
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSAPSS_new_rsapss_load_skey(modBits, eBits, dBits, mod, e, d);

  uint32_t saltLen = Hacl_Hash_Definitions_hash_len(state.range(0));
  uint8_t* salt = (uint8_t*)malloc(saltLen);

  uint32_t sgntLen = modBits / 8;
  uint8_t* sgnt = (uint8_t*)malloc(sgntLen);

  Hacl_RSAPSS_rsapss_sign(state.range(0),
                          modBits,
                          eBits,
                          dBits,
                          skey,
                          saltLen,
                          salt,
                          msg.size(),
                          msg.data(),
                          sgnt);

  uint64_t* pkey = Hacl_RSAPSS_new_rsapss_load_pkey(modBits, eBits, mod, e);

  for (auto _ : state) {
    Hacl_RSAPSS_rsapss_verify(state.range(0),
                              modBits,
                              eBits,
                              pkey,
                              saltLen,
                              sgntLen,
                              sgnt,
                              msg.size(),
                              msg.data());
  }

  free(pkey);
  free(sgnt);
  free(salt);
  free(skey);
  free(mod);
  free(d);
  free(e);
}

BENCHMARK(Rsapss_verify)
  ->Arg(Spec_Hash_Definitions_SHA2_256)
  ->Arg(Spec_Hash_Definitions_SHA2_384)
  ->Arg(Spec_Hash_Definitions_SHA2_512);

BENCHMARK_MAIN();
