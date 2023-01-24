/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "EverCrypt_Curve25519.h"
#include "Hacl_Curve25519_51.h"

#include "util.h"

#if HACL_CAN_COMPILE_VALE
#include "Hacl_Curve25519_64.h"
#endif

static void
setup(bytes& x, bytes& y, bytes& pk_x, bytes& expected_res)
{
  x = hex_to_bytes(
    "c8c15d1fdb88359660950e82475a7146a49a32d051fcf6344d6df2f6b141a15d");
  y = hex_to_bytes(
    "6067ab51f80093e3bf291e29758d8471da29dd75b8635cd4d540c0b6828d8c71");
  expected_res = hex_to_bytes(
    "ee941494300019a41644977e62a4e7e63f871370a4a3f95d02302b8b4f1eea7e");
  pk_x = hex_to_bytes(
    "b2960014ef49f8a2600826857eeb7d6533eec9b40d49c88f160f6f64398c8a47");
}

// -----------------------------------------------------------------------------

static void
HACL_x25519_51(benchmark::State& state)
{
  bytes x, y, pk_x, expected_res;
  setup(x, y, pk_x, expected_res);
  bytes pk(32);
  Hacl_Curve25519_51_secret_to_public(pk.data(), x.data());

  bytes res(32);
  while (state.KeepRunning()) {
    Hacl_Curve25519_51_ecdh(res.data(), y.data(), pk.data());
    if (res != expected_res) {
      state.SkipWithError("Error in x25519");
      break;
    }
  }
}

BENCHMARK(HACL_x25519_51)->Setup(DoSetup);

#if HACL_CAN_COMPILE_VALE
static void
HACL_x25519_64(benchmark::State& state)
{
  if (!vale_x25519_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  bytes x, y, pk_x, expected_res;
  setup(x, y, pk_x, expected_res);
  bytes pk(32);
  Hacl_Curve25519_64_secret_to_public(pk.data(), x.data());

  bytes res(32);
  while (state.KeepRunning()) {
    Hacl_Curve25519_64_ecdh(res.data(), y.data(), pk.data());
    if (res != expected_res) {
      state.SkipWithError("Error in x25519");
      break;
    }
  }
}

BENCHMARK(HACL_x25519_64)->Setup(DoSetup);
#endif

static void
EverCrypt_x25519(benchmark::State& state)
{
  bytes x, y, pk_x, expected_res;
  setup(x, y, pk_x, expected_res);
  bytes pk(32);
  EverCrypt_Curve25519_secret_to_public(pk.data(), x.data());

  bytes res(32);
  while (state.KeepRunning()) {
    EverCrypt_Curve25519_ecdh(res.data(), y.data(), pk.data());
    if (res != expected_res) {
      state.SkipWithError("Error in x25519");
      break;
    }
  }
}

BENCHMARK(EverCrypt_x25519)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_x25519(benchmark::State& state)
{
  EVP_PKEY *pkey_a = NULL, *pkey_b = NULL;
  EVP_PKEY_CTX* pctx_a = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
  EVP_PKEY_CTX* pctx_b = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
  EVP_PKEY_keygen_init(pctx_a);
  EVP_PKEY_keygen_init(pctx_b);
  EVP_PKEY_keygen(pctx_a, &pkey_a);
  EVP_PKEY_keygen(pctx_b, &pkey_b);

  bytes skey(32);
  size_t skey_len = 32;
  while (state.KeepRunning()) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_a, NULL);
    if (EVP_PKEY_derive_init(ctx) != 1) {
      state.SkipWithError("Error in EVP_PKEY_derive_init");
      break;
    }
    if (EVP_PKEY_derive_set_peer(ctx, pkey_b) != 1) {
      state.SkipWithError("Error in EVP_PKEY_derive_set_peer");
      break;
    }
    if (EVP_PKEY_derive(ctx, skey.data(), &skey_len) != 1) {
      state.SkipWithError("Error in EVP_PKEY_derive");
      break;
    }

    if (skey_len != 32) {
      state.SkipWithError("Invalid ECDH");
      break;
    }
    EVP_PKEY_CTX_free(ctx);
  }

  EVP_PKEY_CTX_free(pctx_a);
  EVP_PKEY_CTX_free(pctx_b);
}

BENCHMARK(OpenSSL_x25519)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_x25519_51_base(benchmark::State& state)
{
  bytes x, y, pk_x, expected_res;
  setup(x, y, pk_x, expected_res);

  bytes res(32);
  while (state.KeepRunning()) {
    Hacl_Curve25519_51_secret_to_public(res.data(), x.data());
    if (res != pk_x) {
      state.SkipWithError("Error in x25519 secret to public");
      break;
    }
  }
}

BENCHMARK(HACL_x25519_51_base)->Setup(DoSetup);

#if HACL_CAN_COMPILE_VALE
static void
HACL_x25519_64_base(benchmark::State& state)
{
  if (!vale_x25519_support()) {
    state.SkipWithError("No vec256 support");
    return;
  }

  bytes x, y, pk_x, expected_res;
  setup(x, y, pk_x, expected_res);

  bytes res(32);
  while (state.KeepRunning()) {
    Hacl_Curve25519_64_secret_to_public(res.data(), x.data());
    if (res != pk_x) {
      state.SkipWithError("Error in x25519 secret to public");
      break;
    }
  }
}

BENCHMARK(HACL_x25519_64_base)->Setup(DoSetup);
#endif

static void
EverCrypt_x25519_base(benchmark::State& state)
{
  bytes x, y, pk_x, expected_res;
  setup(x, y, pk_x, expected_res);

  bytes res(32);
  while (state.KeepRunning()) {
    EverCrypt_Curve25519_secret_to_public(res.data(), x.data());
    if (res != pk_x) {
      state.SkipWithError("Error in x25519 secret to public");
      break;
    }
  }
}

BENCHMARK(EverCrypt_x25519_base)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_x25519_base(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(OpenSSL_x25519_base)->Setup(DoSetup);
#endif

BENCHMARK_MAIN();
