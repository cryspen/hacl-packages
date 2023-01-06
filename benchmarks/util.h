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
