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

template<class... Args>
void
HACL_Rsapss_sign(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);
  Spec_Hash_Definitions_hash_alg algorithm = std::get<0>(args_tuple);

  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSA_new_rsa_load_skey(modBits, eBits, dBits, mod, e, d);

  uint32_t saltLen = Hacl_Hash_Definitions_hash_len(algorithm);
  bytes salt(saltLen);

  uint32_t sgntLen = modBits / 8;
  bytes sgnt(sgntLen);

  for (auto _ : state) {
    Hacl_RSAPSS_rsapss_sign(algorithm,
                            modBits,
                            eBits,
                            dBits,
                            skey,
                            saltLen,
                            salt.data(),
                            msg.size(),
                            msg.data(),
                            sgnt.data());
  }

  free(skey);
  free(mod);
  free(d);
  free(e);
}

BENCHMARK_CAPTURE(HACL_Rsapss_sign, sha2_256, Spec_Hash_Definitions_SHA2_256)
  ->Setup(DoSetup);
BENCHMARK_CAPTURE(HACL_Rsapss_sign, sha2_384, Spec_Hash_Definitions_SHA2_384)
  ->Setup(DoSetup);
BENCHMARK_CAPTURE(HACL_Rsapss_sign, sha2_512, Spec_Hash_Definitions_SHA2_512)
  ->Setup(DoSetup);

template<class... Args>
void
HACL_Rsapss_verify(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);
  Spec_Hash_Definitions_hash_alg algorithm = std::get<0>(args_tuple);

  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSA_new_rsa_load_skey(modBits, eBits, dBits, mod, e, d);

  uint32_t saltLen = Hacl_Hash_Definitions_hash_len(algorithm);
  bytes salt(saltLen);

  uint32_t sgntLen = modBits / 8;
  bytes sgnt(sgntLen);

  Hacl_RSAPSS_rsapss_sign(algorithm,
                          modBits,
                          eBits,
                          dBits,
                          skey,
                          saltLen,
                          salt.data(),
                          msg.size(),
                          msg.data(),
                          sgnt.data());

  uint64_t* pkey = Hacl_RSA_new_rsa_load_pkey(modBits, eBits, mod, e);

  for (auto _ : state) {
    Hacl_RSAPSS_rsapss_verify(algorithm,
                              modBits,
                              eBits,
                              pkey,
                              saltLen,
                              sgntLen,
                              sgnt.data(),
                              msg.size(),
                              msg.data());
  }

  free(pkey);
  free(skey);
  free(mod);
  free(d);
  free(e);
}

BENCHMARK_CAPTURE(HACL_Rsapss_verify, sha2_256, Spec_Hash_Definitions_SHA2_256)
  ->Setup(DoSetup);
BENCHMARK_CAPTURE(HACL_Rsapss_verify, sha2_384, Spec_Hash_Definitions_SHA2_384)
  ->Setup(DoSetup);
BENCHMARK_CAPTURE(HACL_Rsapss_verify, sha2_512, Spec_Hash_Definitions_SHA2_512)
  ->Setup(DoSetup);

BENCHMARK_MAIN();
