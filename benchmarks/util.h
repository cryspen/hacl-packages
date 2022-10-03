#pragma once

// Benchmark utilities and includes.

#include <benchmark/benchmark.h>

// OpenSSL
#ifndef NO_OPENSSL
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <vector>

#include "EverCrypt_AutoConfig2.h"
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
