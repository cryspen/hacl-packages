/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "Libcrux_Kem_Kyber_Kyber768.h"
#include "util.h"

static void
kyber768_key_generation(benchmark::State& state)
{
  uint8_t randomness[64];
  generate_random(randomness, 64);

  uint8_t public_key[KYBER768_PUBLICKEYBYTES];
  uint8_t secret_key[KYBER768_SECRETKEYBYTES];

  for (auto _ : state) {
    Libcrux_Kyber768_GenerateKeyPair(public_key, secret_key, randomness);
  }
}

static void
kyber768_encapsulation(benchmark::State& state)
{
  uint8_t randomness[32];
  generate_random(randomness, 32);

  uint8_t public_key[KYBER768_PUBLICKEYBYTES];
  uint8_t secret_key[KYBER768_SECRETKEYBYTES];

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];

  Libcrux_Kyber768_GenerateKeyPair(public_key, secret_key, randomness);

  for (auto _ : state) {
    Libcrux_Kyber768_Encapsulate(
      ciphertext, sharedSecret, &public_key, randomness);
  }
}

static void
kyber768_decapsulation(benchmark::State& state)
{
  uint8_t randomness[64];

  uint8_t public_key[KYBER768_PUBLICKEYBYTES];
  uint8_t secret_key[KYBER768_SECRETKEYBYTES];

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];

  generate_random(randomness, 64);
  Libcrux_Kyber768_GenerateKeyPair(public_key, secret_key, randomness);

  generate_random(randomness, 32);
  Libcrux_Kyber768_Encapsulate(
    ciphertext, sharedSecret, &public_key, randomness);

  for (auto _ : state) {
    Libcrux_Kyber768_Decapsulate(sharedSecret, &ciphertext, &secret_key);
  }
}

BENCHMARK(kyber768_key_generation)->Setup(DoSetup);
BENCHMARK(kyber768_encapsulation)->Setup(DoSetup);
BENCHMARK(kyber768_decapsulation)->Setup(DoSetup);

BENCHMARK_MAIN();
