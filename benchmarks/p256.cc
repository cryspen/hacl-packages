/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */
#include "util.h"

#include "Hacl_P256.h"

static void
P256_SHA256_ECDSA_Sign(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "f6bbfeced354cfcd0fb7e647f3dca33116b1287b07d6a2dcc6d545248e4a6489");
  assert(Hacl_P256_validate_private_key(sk.data()));

  bytes pk(64);
  bytes pk_compressed = hex_to_bytes(
    "02e5e37c0dfc63da709d3381613f672bc66a7aa5d0084d1bfea663f6e70e9d65f2");
  bool result = Hacl_P256_compressed_to_raw(pk_compressed.data(), pk.data());
  assert(result);

  bytes signature(64);
  bytes msg = hex_to_bytes(
    "1401e603f155206c4892cd3d7cbc93a4d0d9d2eda706c4f50d279393bc083cde2a07bde74f"
    "9b367dbc065e1a1e69d995402fa5343db0bd49666d3ed4b23c0ab60e39d7f49d93c9caf40d"
    "c86996ebd71c0176924a1e0478c4b97f0711935dbc110d98a3bd642a2883c1112db52ef9b3"
    "84547b0e440e39714a3422597849dbd0d1e1b8be92c5cec6a767d67b0b110f870b8fd8dad9"
    "15378b458da4ecfa385a5bfc77403837fc3e92e5f14cad22c4e15aaebc4a434c02bc10ef44"
    "b7d0cca019947ead831fa9446858e03182ac48682fad2a78890ddd10fdaa3b516ad899643f"
    "b882d34ddf0ac8051453b638bb9e217ebad92acbfbf6a9e4b2b1cd899fde59a20543ce4a5b"
    "37690fcf8c17f5236b2769ba31516a30ad07024dd2fdaf0f1942dff2c42ac121b0693ad83b"
    "a3e290cddf3d24be55622be07645551510cd70ecca0fc86ae6bc6f48ac2688e1fddf0f48a9"
    "4c07c21834422af216babc8968803c09d0fa7ea58daba0d20dabb5a6db175c013e29e911be"
    "ba8087bd4ee55479311340cb7dfb7b7e668f7003c755e2070e1edb399621f11d8a2e4f4dd4"
    "01f23f802872254aa531c1006c6f2403cbd9063f99f3864bf3dc535ae822559ac82b66d3b5"
    "b5a9f52ace7c9a6b40a2a184b7da200c5b86d61ef079767516af00116791aa740618b97e66"
    "9ea78b19e99508d9cac6da9558587ab16094d0bcc8bd76e1b38efda0c10f02f7e46f9ced38"
    "fe8fe334471b4455392a0a367dcd62b5b448303aaab24ceaf547d4bce89700f9b126fb7119"
    "9f15ba5cdfb6025c132aeec6d98c329067575c8089d9a32267e25f022a50c2f5e4cf45fca6"
    "33546e9e010a5e7e2c022eff48ea4253bdcb2663cf87bad1ebce2424353bc40faba6d6daa2"
    "97ec96ac970bd4d1743bd45a269496ae4b94212be1e5541db5d8c0ba0e852e3f0fcfbc6c7e"
    "549ea5ec6bdf0d34de7fcae3fbf35d76149cd3613966ef0f74ce588773bd3ea198a74865df"
    "854b16e90969f733c01230eb470c10e2d069ebeeb3ea81c7ce48ebf5804968a024d81aaff9"
    "148f6c7a6e1c2f66991a07cf98");
  bytes nonce = hex_to_bytes(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  for (auto _ : state) {
    bool result = Hacl_P256_ecdsa_sign_p256_sha2(
      signature.data(), msg.size(), msg.data(), sk.data(), nonce.data());
    assert(result);
  }
}

static void
P256_SHA256_ECDSA_Verify(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "f6bbfeced354cfcd0fb7e647f3dca33116b1287b07d6a2dcc6d545248e4a6489");
  assert(Hacl_P256_validate_private_key(sk.data()));

  bytes pk(64);
  bytes pk_compressed = hex_to_bytes(
    "02e5e37c0dfc63da709d3381613f672bc66a7aa5d0084d1bfea663f6e70e9d65f2");
  bool result = Hacl_P256_compressed_to_raw(pk_compressed.data(), pk.data());
  assert(result);

  bytes signature(64);
  bytes msg = hex_to_bytes(
    "1401e603f155206c4892cd3d7cbc93a4d0d9d2eda706c4f50d279393bc083cde2a07bde74f"
    "9b367dbc065e1a1e69d995402fa5343db0bd49666d3ed4b23c0ab60e39d7f49d93c9caf40d"
    "c86996ebd71c0176924a1e0478c4b97f0711935dbc110d98a3bd642a2883c1112db52ef9b3"
    "84547b0e440e39714a3422597849dbd0d1e1b8be92c5cec6a767d67b0b110f870b8fd8dad9"
    "15378b458da4ecfa385a5bfc77403837fc3e92e5f14cad22c4e15aaebc4a434c02bc10ef44"
    "b7d0cca019947ead831fa9446858e03182ac48682fad2a78890ddd10fdaa3b516ad899643f"
    "b882d34ddf0ac8051453b638bb9e217ebad92acbfbf6a9e4b2b1cd899fde59a20543ce4a5b"
    "37690fcf8c17f5236b2769ba31516a30ad07024dd2fdaf0f1942dff2c42ac121b0693ad83b"
    "a3e290cddf3d24be55622be07645551510cd70ecca0fc86ae6bc6f48ac2688e1fddf0f48a9"
    "4c07c21834422af216babc8968803c09d0fa7ea58daba0d20dabb5a6db175c013e29e911be"
    "ba8087bd4ee55479311340cb7dfb7b7e668f7003c755e2070e1edb399621f11d8a2e4f4dd4"
    "01f23f802872254aa531c1006c6f2403cbd9063f99f3864bf3dc535ae822559ac82b66d3b5"
    "b5a9f52ace7c9a6b40a2a184b7da200c5b86d61ef079767516af00116791aa740618b97e66"
    "9ea78b19e99508d9cac6da9558587ab16094d0bcc8bd76e1b38efda0c10f02f7e46f9ced38"
    "fe8fe334471b4455392a0a367dcd62b5b448303aaab24ceaf547d4bce89700f9b126fb7119"
    "9f15ba5cdfb6025c132aeec6d98c329067575c8089d9a32267e25f022a50c2f5e4cf45fca6"
    "33546e9e010a5e7e2c022eff48ea4253bdcb2663cf87bad1ebce2424353bc40faba6d6daa2"
    "97ec96ac970bd4d1743bd45a269496ae4b94212be1e5541db5d8c0ba0e852e3f0fcfbc6c7e"
    "549ea5ec6bdf0d34de7fcae3fbf35d76149cd3613966ef0f74ce588773bd3ea198a74865df"
    "854b16e90969f733c01230eb470c10e2d069ebeeb3ea81c7ce48ebf5804968a024d81aaff9"
    "148f6c7a6e1c2f66991a07cf98");
  bytes nonce = hex_to_bytes(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  assert(Hacl_P256_ecdsa_sign_p256_sha2(
    signature.data(), msg.size(), msg.data(), sk.data(), nonce.data()));

  for (auto _ : state) {
    bytes r(signature.begin(), signature.begin() + 32);
    bytes s(signature.begin() + 32, signature.end());
    bool result = Hacl_P256_ecdsa_verif_p256_sha2(
      msg.size(), msg.data(), pk.data(), r.data(), s.data());
    assert(result);
  }
}

static void
P256_ECDH(benchmark::State& state)
{
  bytes public_key = hex_to_bytes(
    "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93"
    "a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf");
  bytes plain_public_key(64);
  assert(
    Hacl_P256_uncompressed_to_raw(public_key.data(), plain_public_key.data()));

  bytes plain_private_key = hex_to_bytes(
    "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");

  bytes shared(64);

  for (auto _ : state) {
    bool result = Hacl_P256_dh_responder(
      shared.data(), plain_public_key.data(), plain_private_key.data());
    assert(result);
  }
}

#ifndef NO_OPENSSL
static void
Openssl_P256_ECDH(benchmark::State& state)
{
  // XXX: Note that the EC_ APIs are deprecated in OpenSSL 3.
  //      We ignore this for now though.
  EC_KEY* sk_a = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY* sk_b = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  EC_KEY_generate_key(sk_a);
  EC_KEY_generate_key(sk_b);

  const EC_POINT* pk_a = EC_KEY_get0_public_key(sk_a);
  const EC_POINT* pk_b = EC_KEY_get0_public_key(sk_b);

  char secret_a[32], secret_b[32];
  size_t slen_b = ECDH_compute_key(secret_b, 32, pk_a, sk_b, NULL);
  while (state.KeepRunning()) {
    size_t slen_a = ECDH_compute_key(secret_a, 32, pk_b, sk_a, NULL);
    if (slen_a != slen_b || memcmp(secret_a, secret_b, slen_a) != 0) {
      state.SkipWithError("Invalid ECDH");
      break;
    }
  }

  EC_KEY_free(sk_a);
  EC_KEY_free(sk_b);
}

static void
Openssl_P256_ECDSA_Sign(benchmark::State& state)
{
  // Generate low level keys first.
  EC_KEY* sk_a = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_generate_key(sk_a);

  // Now load them into the EVP world.
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (EVP_PKEY_assign_EC_KEY(pkey, sk_a) != 1) {
    state.SkipWithError("Unable to create EVP key");
    return;
  }

  int expected_sig_len = ECDSA_size(sk_a);
  size_t sig_len = expected_sig_len;

  bytes signature(expected_sig_len);
  bytes data(128);
  RAND_bytes(data.data(), 128);
  while (state.KeepRunning()) {
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
      state.SkipWithError("Unable to create EVP context");
      break;
    }
    if (EVP_DigestSignUpdate(mctx, data.data(), data.size()) != 1) {
      state.SkipWithError("Unable to update EVP context");
      break;
    }
    sig_len = expected_sig_len;
    int result = EVP_DigestSignFinal(mctx, signature.data(), &sig_len);
    if (result != 1 || expected_sig_len < sig_len) {
      state.SkipWithError("Unable to generate signature");
      break;
    }
    EVP_MD_CTX_free(mctx);
  }

  const EC_POINT* pk_a = EC_KEY_get0_public_key(sk_a);
  EC_KEY* key_pk_a = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!EC_KEY_set_public_key(key_pk_a, pk_a)) {
    state.SkipWithError("Unable to create public EVP key");
    return;
  }
  EVP_PKEY* ppkey = EVP_PKEY_new();
  if (EVP_PKEY_assign_EC_KEY(ppkey, key_pk_a) != 1) {
    state.SkipWithError("Unable to create public EVP key");
    return;
  }

  EVP_MD_CTX* md_ctx_verify = EVP_MD_CTX_new();
  if (!EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sha256(), NULL, ppkey) ||
      !EVP_DigestVerifyUpdate(md_ctx_verify, data.data(), data.size()) ||
      !EVP_DigestVerifyFinal(md_ctx_verify, signature.data(), sig_len)) {
    state.SkipWithError("Error verifying signature");
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_free(ppkey);
}

static void
Openssl_P256_ECDSA_Verify(benchmark::State& state)
{
  // Generate low level keys first.
  EC_KEY* sk_a = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_generate_key(sk_a);

  // Now load them into the EVP world.
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (EVP_PKEY_assign_EC_KEY(pkey, sk_a) != 1) {
    state.SkipWithError("Unable to create EVP key");
    return;
  }

  int expected_sig_len = ECDSA_size(sk_a);

  bytes signature(expected_sig_len);
  bytes data(128);
  RAND_bytes(data.data(), 128);

  EVP_MD_CTX* mctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
    state.SkipWithError("Unable to create EVP context");
    return;
  }
  if (EVP_DigestSignUpdate(mctx, data.data(), data.size()) != 1) {
    state.SkipWithError("Unable to update EVP context");
    return;
  }
  size_t sig_len = expected_sig_len;
  int result = EVP_DigestSignFinal(mctx, signature.data(), &sig_len);
  if (result != 1 || expected_sig_len < sig_len) {
    state.SkipWithError("Unable to generate signature");
    return;
  }
  EVP_MD_CTX_free(mctx);

  const EC_POINT* pk_a = EC_KEY_get0_public_key(sk_a);
  EC_KEY* key_pk_a = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!EC_KEY_set_public_key(key_pk_a, pk_a)) {
    state.SkipWithError("Unable to create public EVP key");
    return;
  }
  EVP_PKEY* ppkey = EVP_PKEY_new();
  if (EVP_PKEY_assign_EC_KEY(ppkey, key_pk_a) != 1) {
    state.SkipWithError("Unable to create public EVP key");
    return;
  }

  while (state.KeepRunning()) {
    EVP_MD_CTX* md_ctx_verify = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sha256(), NULL, ppkey) !=
        1) {
      state.SkipWithError("Error in EVP_DigestVerifyInit");
      break;
    }
    if (EVP_DigestVerifyUpdate(md_ctx_verify, data.data(), data.size()) != 1) {
      state.SkipWithError("Error in EVP_DigestVerifyUpdate");
      break;
    }
    if (EVP_DigestVerifyFinal(md_ctx_verify, signature.data(), sig_len) != 1) {
      state.SkipWithError("Error in EVP_DigestVerifyFinal");
      break;
    }
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_free(ppkey);
}
#endif

BENCHMARK(P256_SHA256_ECDSA_Sign);
BENCHMARK(P256_SHA256_ECDSA_Verify);
#ifndef NO_OPENSSL
BENCHMARK(Openssl_P256_ECDSA_Sign);
BENCHMARK(Openssl_P256_ECDSA_Verify);
#endif
BENCHMARK(P256_ECDH);
#ifndef NO_OPENSSL
BENCHMARK(Openssl_P256_ECDH);
#endif

BENCHMARK_MAIN();
