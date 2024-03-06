/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "Hacl_RSA.h"

#include "util.h"


void
HACL_RSA_enc(benchmark::State& state)
{
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSA_new_rsa_load_skey(modBits, eBits, dBits, mod, e, d);
  uint64_t* pkey = Hacl_RSA_new_rsa_load_pkey(modBits, eBits, mod, e);

  uint8_t msg[256] = {0};
  uint8_t cipher[256] = {0};

  for (auto _ : state) {
    Hacl_RSA_rsa_enc(modBits,
                     eBits,
                     pkey,
                     msg,
                     cipher);
  }

  free(skey);
  free(pkey);
  free(mod);
  free(d);
  free(e);
}

BENCHMARK(HACL_RSA_enc)->Setup(DoSetup);

void
HACL_RSA_dec(benchmark::State& state)
{
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSA_new_rsa_load_skey(modBits, eBits, dBits, mod, e, d);
  uint64_t* pkey = Hacl_RSA_new_rsa_load_pkey(modBits, eBits, mod, e);

  uint8_t msg[256] = {0};
  uint8_t cipher[256] = {0};

  Hacl_RSA_rsa_enc(modBits,
                   eBits,
                   pkey,
                   msg,
                   cipher);
  
  for (auto _ : state) {
    Hacl_RSA_rsa_dec(modBits,
                     eBits,
                     dBits,
                     skey,
                     cipher,
                     msg);
  }

  free(pkey);
  free(skey);
  free(mod);
  free(d);
  free(e);
}

BENCHMARK(HACL_RSA_dec)->Setup(DoSetup);

BENCHMARK_MAIN();
