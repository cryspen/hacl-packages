/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "Hacl_EC_K256.h"
#include "Hacl_K256_ECDSA.h"

#include "util.h"

static void
HACL_K256_ECDSA_Sign(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "a32aa1699dcaf84c231dc805981942aa8793b4256d6a21de3e78c9036d39cc1f");

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
  bytes nonce = bytes(32, 'A');

  for (auto _ : state) {
    Hacl_K256_ECDSA_ecdsa_sign_sha256(
      signature.data(), msg.size(), msg.data(), sk.data(), nonce.data());
  }
}

BENCHMARK(HACL_K256_ECDSA_Sign)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_K256_ECDSA_Sign(benchmark::State& state)
{
  // Generate low level keys first.
  EC_KEY* sk_a = EC_KEY_new_by_curve_name(NID_secp256k1);
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
  EC_KEY* key_pk_a = EC_KEY_new_by_curve_name(NID_secp256k1);
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
      !EVP_DigestVerifyFinal(
        md_ctx_verify, signature.data(), signature.size())) {
    state.SkipWithError("Error verifying signature");
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_free(ppkey);
}

BENCHMARK(OpenSSL_K256_ECDSA_Sign)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_K256_ECDSA_Sign_Normalized(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "a32aa1699dcaf84c231dc805981942aa8793b4256d6a21de3e78c9036d39cc1f");

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
  bytes nonce = bytes(32, 'A');

  for (auto _ : state) {
    Hacl_K256_ECDSA_secp256k1_ecdsa_sign_sha256(
      signature.data(), msg.size(), msg.data(), sk.data(), nonce.data());
  }
}

BENCHMARK(HACL_K256_ECDSA_Sign_Normalized)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
OpenSSL_K256_ECDSA_Sign_Normalized(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(OpenSSL_K256_ECDSA_Sign_Normalized)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_K256_ECDSA_Verify(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "a32aa1699dcaf84c231dc805981942aa8793b4256d6a21de3e78c9036d39cc1f");
  bytes pk_compressed = hex_to_bytes(
    "029d2ad65c5ef50e1651d78825dae280499155f5053def90487fc0282de763a49d");
  bytes pk(64);
  bool res = Hacl_K256_ECDSA_public_key_compressed_to_raw(pk.data(),
                                                          pk_compressed.data());

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
  bytes nonce = bytes(32, 'A');

  Hacl_K256_ECDSA_ecdsa_sign_sha256(
    signature.data(), msg.size(), msg.data(), sk.data(), nonce.data());

  for (auto _ : state) {
    Hacl_K256_ECDSA_ecdsa_verify_sha256(
      msg.size(), msg.data(), pk.data(), signature.data());
  }
}

BENCHMARK(HACL_K256_ECDSA_Verify)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
Openssl_K256_ECDSA_Verify(benchmark::State& state)
{
  // Generate low level keys first.
  EC_KEY* sk_a = EC_KEY_new_by_curve_name(NID_secp256k1);
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
  EC_KEY* key_pk_a = EC_KEY_new_by_curve_name(NID_secp256k1);
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

BENCHMARK(Openssl_K256_ECDSA_Verify)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_K256_ECDSA_Verify_Normalized(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "a32aa1699dcaf84c231dc805981942aa8793b4256d6a21de3e78c9036d39cc1f");
  bytes pk_compressed = hex_to_bytes(
    "029d2ad65c5ef50e1651d78825dae280499155f5053def90487fc0282de763a49d");
  bytes pk(64);
  bool res = Hacl_K256_ECDSA_public_key_compressed_to_raw(pk.data(),
                                                          pk_compressed.data());

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
  bytes nonce = bytes(32, 'A');

  Hacl_K256_ECDSA_secp256k1_ecdsa_sign_sha256(
    signature.data(), msg.size(), msg.data(), sk.data(), nonce.data());

  for (auto _ : state) {
    Hacl_K256_ECDSA_secp256k1_ecdsa_verify_sha256(
      msg.size(), msg.data(), pk.data(), signature.data());
  }
}

BENCHMARK(HACL_K256_ECDSA_Verify_Normalized)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
Openssl_K256_ECDSA_Verify_Normalized(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(Openssl_K256_ECDSA_Verify_Normalized)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_K256_ECDH(benchmark::State& state)
{
  bytes pk_raw = hex_to_bytes(
    "d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b396812ea"
    "1686e7472e9692eaf3e958e50e9500d3b4c77243db1f2acd67ba9cc4");
  bytes pk_compressed(33);
  Hacl_K256_ECDSA_public_key_compressed_from_raw(pk_compressed.data(),
                                                 pk_raw.data());
  vector<uint64_t> public_key(15);
  if (!Hacl_EC_K256_point_decompress(pk_compressed.data(), public_key.data())) {
    state.SkipWithError("Invalid public key");
    return;
  }

  bytes private_key = hex_to_bytes(
    "f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254");

  bytes shared(64);
  vector<uint64_t> shared_projective(15);
  for (auto _ : state) {
    Hacl_EC_K256_point_mul(
      private_key.data(), public_key.data(), shared_projective.data());
    Hacl_EC_K256_point_compress(shared_projective.data(), shared.data());
  }
}

BENCHMARK(HACL_K256_ECDH)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
Openssl_K256_ECDH(benchmark::State& state)
{
  // XXX: Note that the EC_ APIs are deprecated in OpenSSL 3.
  //      We ignore this for now though.
  EC_KEY* sk_a = EC_KEY_new_by_curve_name(NID_secp256k1);
  EC_KEY* sk_b = EC_KEY_new_by_curve_name(NID_secp256k1);

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

BENCHMARK(Openssl_K256_ECDH)->Setup(DoSetup);
#endif

// -----------------------------------------------------------------------------

static void
HACL_K256_ECDH_NoCompress(benchmark::State& state)
{
  bytes pk_raw = hex_to_bytes(
    "d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b396812ea"
    "1686e7472e9692eaf3e958e50e9500d3b4c77243db1f2acd67ba9cc4");
  bytes pk_compressed(33);
  Hacl_K256_ECDSA_public_key_compressed_from_raw(pk_compressed.data(),
                                                 pk_raw.data());
  vector<uint64_t> public_key(15);
  if (!Hacl_EC_K256_point_decompress(pk_compressed.data(), public_key.data())) {
    state.SkipWithError("Invalid public key");
    return;
  }

  bytes private_key = hex_to_bytes(
    "f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254");

  vector<uint64_t> shared_projective(15);
  for (auto _ : state) {
    Hacl_EC_K256_point_mul(
      private_key.data(), public_key.data(), shared_projective.data());
  }
}

BENCHMARK(HACL_K256_ECDH_NoCompress)->Setup(DoSetup);

#ifndef NO_OPENSSL
static void
Openssl_K256_ECDH_NoCompress(benchmark::State& state)
{
  // TODO
  state.SkipWithError("Unimplemented");
}

BENCHMARK(Openssl_K256_ECDH_NoCompress)->Setup(DoSetup);
#endif

BENCHMARK_MAIN();
