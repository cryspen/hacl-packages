#pragma once

// Benchmark utilities and includes.

#include <benchmark/benchmark.h>

// OpenSSL
#ifndef NO_OPENSSL
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <vector>

#include "EverCrypt_AutoConfig2.h"
#include "EverCrypt_DRBG.h"
#include "config.h"
#include "hacl-cpu-features.h"

using namespace ::std;
typedef vector<uint8_t> bytes;

string
bytes_to_hex(const bytes& data)
{
  stringstream hex(ios_base::out);
  hex.flags(ios::hex);
  for (const auto& byte : data) {
    hex << setw(2) << setfill('0') << int(byte);
  }
  return hex.str();
}

bytes
hex_to_bytes(const string& hex)
{
  if (hex.length() % 2 == 1) {
    throw invalid_argument("Odd-length hex string");
  }

  int len = static_cast<int>(hex.length()) / 2;
  bytes out(len);
  for (int i = 0; i < len; i += 1) {
    string byte = hex.substr(2 * i, 2);
    out[i] = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
  }

  return out;
}

void
cpu_init()
{
  hacl_init_cpu_features();
  EverCrypt_AutoConfig2_init();
}

static void
DoSetup(const benchmark::State& state)
{
  cpu_init();
}

bool
vec128_support()
{
  return hacl_vec128_support() || EverCrypt_AutoConfig2_has_vec128();
}

bool
vec256_support()
{
  return hacl_vec256_support() || EverCrypt_AutoConfig2_has_vec256();
}

vector<uint8_t>
from_hex(const string& hex)
{
  if (hex.length() % 2 == 1) {
    throw invalid_argument("Odd-length hex string");
  }

  int len = static_cast<int>(hex.length()) / 2;
  vector<uint8_t> out(len);
  for (int i = 0; i < len; i += 1) {
    string byte = hex.substr(2 * i, 2);
    out[i] = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
  }

  return out;
}

void
crypto_box_keypair_alice(uint8_t* sk, uint8_t* pk)
{
  bytes sk_bytes = from_hex(
    "2a10d44276462147f34a899ac72c9fabfefa60591bc22d8c44fe4819c0151080");
  std::copy(sk_bytes.begin(), sk_bytes.end(), sk);

  bytes pk_bytes = from_hex(
    "ae496ef306c7c0bda37e8e4076238d2fd433004fdf047ccd2cee6be7fb731136");
  std::copy(pk_bytes.begin(), pk_bytes.end(), pk);
}

void
crypto_box_keypair_bob(uint8_t* sk, uint8_t* pk)
{
  bytes sk_bytes = from_hex(
    "9ea6ce368aea3c09577f8e57118acb9cdf9e2b562d035c243a582bd01b0795ed");
  std::copy(sk_bytes.begin(), sk_bytes.end(), sk);

  bytes pk_bytes = from_hex(
    "2af1a3b5ed0486f895a54fdd2dfbcd0daa1e0982ef33eeb0d693d6d502c5901a");
  std::copy(pk_bytes.begin(), pk_bytes.end(), pk);
}

void
generate_random(uint8_t* output, uint32_t output_len)
{
  EverCrypt_DRBG_state_s_s* state =
    EverCrypt_DRBG_create(Spec_Hash_Definitions_SHA2_256);
  EverCrypt_DRBG_instantiate(state, (uint8_t*)"example", 7);
  EverCrypt_DRBG_generate(output, state, output_len, (uint8_t*)"", 0);
  EverCrypt_DRBG_uninstantiate(state);
}

// Only used in examples. Do not use otherwise.
void
generate_rsapss_key(uint8_t** e,
                    uint32_t* eBits,
                    uint8_t** d,
                    uint32_t* dBits,
                    uint8_t** n,
                    uint32_t* nBits)
{
  bytes _e = from_hex("010001");
  bytes _d = from_hex(
    "12ddcf5652e462db7bd689e1604cf27dacb7435105880c8acac24ef9302c29bc819eaee139"
    "66d471114053e17d8ae3bca57460d1b177f8bd37bfbbee243cb5e3dde2ae34dff6b3095939"
    "c5c74d56a674a12b270d8213a6268ec3f332dd9cf746ba097b6ce8490be4dabfb83d02560e"
    "da766a3551681725230f31f7a67bc8f5e8968103426eac652a30893251431e434597c06487"
    "b05b49b7a6d2e4d263de4f7e7788471b19e8aa64f3dce41bf1f55f057d50187f95379a7f93"
    "09f6afa62ceca1e988df7c8dc484101349ca131fe9c4b4d42c63c788dc6e6ce93f11a0567c"
    "2830022c5ee73c1c55c668e2cdcc1fb88c91bfdd33e014c29cb8af2e84c14cf9f8ad");
  bytes _n = from_hex(
    "bb6707ae65f4ee9e65ee1a1c08b431e556cd1000dc5358b97098c9546de8ef9b5a227cbd89"
    "fbca5fa1b0e7527cb4fd66d934f0edc166cf6f7944fb44997a0023885c319f25b7927b0c03"
    "74132f5ab38de2bfb25228ab4cf4c3932662d4af7dab73e2da520016b7df4d97575ffb90ff"
    "b0bda1b791f6e09cd70bc04bdc19b757279f271476fe774737ab816d0da86254a45cd98d5b"
    "ce77ccd950e1f16f572a4e45a292b501e6394e2e49cf547302222529cb754d3d255512fe83"
    "5874020d9f8662e22c000c8af6247be141bab2abf4a712ee1590d260bf3bb907a151604ec9"
    "354fc806f86eeaeb4df53dd822412189567fb5fc0bc2082a7c4f613834a72f985c27");

  *eBits = (uint32_t)_e.size() * 8;
  *dBits = (uint32_t)_d.size() * 8;
  *nBits = (uint32_t)_n.size() * 8;

  *e = (uint8_t*)malloc(*eBits * 8);
  *d = (uint8_t*)malloc(*dBits * 8);
  *n = (uint8_t*)malloc(*nBits * 8);

  std::copy(_e.begin(), _e.end(), *e);
  std::copy(_d.begin(), _d.end(), *d);
  std::copy(_n.begin(), _n.end(), *n);
}

vector<bytes>
chunk(bytes data, size_t chunk_size)
{
  vector<bytes> out(data.size() / chunk_size);

  auto start = data.begin();
  auto end = data.end();

  while (start != end) {
    auto next = distance(start, end) >= chunk_size ? start + chunk_size : end;

    out.emplace_back(start, next);
    start = next;
  }

  return out;
}

static void
Range(benchmark::internal::Benchmark* b)
{
  b->Arg(0);
  for (size_t i = 16; i <= 16 * 1024 * 1024; i = i * 16) {
    b->Arg(i);
  }
}

#ifndef NO_OPENSSL
template<class... Args>
void
OpenSSL_hash_oneshot(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);

  auto algorithm = std::get<0>(args_tuple);
  const bytes input = std::get<1>(args_tuple);
  const size_t digest_len = std::get<2>(args_tuple);
  const bytes expected_digest = std::get<3>(args_tuple);

  bytes digest(digest_len, 0);
  unsigned int len = digest.size();

  for (auto _ : state) {
    EVP_Digest(
      input.data(), input.size(), digest.data(), &len, algorithm, NULL);
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect digest.");
  }
}

template<class... Args>
void
OpenSSL_hash_streaming(benchmark::State& state, Args&&... args)
{
  auto args_tuple = std::make_tuple(std::move(args)...);

  auto algorithm = std::get<0>(args_tuple);
  const bytes input = std::get<1>(args_tuple);
  const size_t chunk_len = std::get<2>(args_tuple);
  const size_t digest_len = std::get<3>(args_tuple);
  const bytes expected_digest = std::get<4>(args_tuple);

  bytes digest(digest_len, 0);

  for (auto _ : state) {
    if (input != bytes(1000, 0x37)) {
      state.SkipWithError("Incorrect input.");
    }

    // Init
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, algorithm);

    // Update
    for (auto chunk : chunk(input, chunk_len)) {
      EVP_DigestUpdate(ctx, chunk.data(), chunk.size());
    }

    // Finish
    unsigned int len = digest.size();
    EVP_DigestFinal_ex(ctx, digest.data(), &len);
    EVP_MD_CTX_free(ctx);
  }

  if (digest != expected_digest) {
    state.SkipWithError("Incorrect digest.");
    return;
  }
}
#endif
