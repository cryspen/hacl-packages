#pragma once

#include <stdint.h>
#include <stdio.h>
#include <vector>

#include "EverCrypt_DRBG.h"

using namespace std;

typedef vector<uint8_t> bytes;

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

string
bytes_to_hex(const vector<uint8_t>& data)
{
  stringstream hex(ios_base::out);
  hex.flags(ios::hex);
  for (const auto& byte : data) {
    hex << setw(2) << setfill('0') << int(byte);
  }
  return hex.str();
}

string
array_to_hex(const uint8_t* data, size_t len)
{
  stringstream hex(ios_base::out);
  hex.flags(ios::hex);
  for (size_t i = 0; i < len; i++) {
    hex << setw(2) << setfill('0') << int(data[i]);
  }
  return hex.str();
}

static inline bool
compare_and_print(size_t len, uint8_t* comp, uint8_t* exp)
{
  bool ok = memcmp(exp, comp, len) == 0;
  if (!ok) {
    printf(" ERROR\n");
    printf("   computed: %s\n", array_to_hex(comp, len).c_str());
    printf("   expected: %s\n", array_to_hex(exp, len).c_str());
  }
  return ok;
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

// Split a vector of uint8_t (bytes) into slices according to lengths.
//
// Examples:
//   "ABCDEF" x 0      --> "", "ABCDEF"
//   "ABCDEF" x 1      --> "A", "BCDEF"
//   "ABCDEF" x 0,1    --> "", "A", "BCDEF"
//   "ABCDEF" x 1,1,0  --> "A", "B", "", "CDEF"
//   "ABCDEF" x 3,3    --> "ABC", "DEF"
//   "ABCDEF" x 6      --> "ABCDEF"
vector<bytes>
split_by_index_list(const bytes data, const vector<size_t> lenghts)
{
  vector<bytes> out;

  bytes remaining = data;
  for (size_t split : lenghts) {
    if (remaining.size() >= split) {
      bytes slice = bytes(remaining.begin(), remaining.begin() + split);
      remaining = bytes(remaining.begin() + split, remaining.end());

      out.push_back(slice);
    }
  }

  if (!remaining.empty()) {
    out.push_back(remaining);
  }

  return out;
}

vector<vector<size_t>>
make_lengths()
{
  return { {}, { 0, 1, 2, 3, 4, 5, 8, 9, 16, 17, 32, 33, 64, 65, 128, 129 } };
}

// Only used in examples. Do not use otherwise.
void
generate_random(uint8_t* output, uint32_t output_len)
{
  EverCrypt_DRBG_state_s_s* state =
    EverCrypt_DRBG_create(Spec_Hash_Definitions_SHA2_256);
  EverCrypt_DRBG_instantiate(state, (uint8_t*)"example", 7);
  EverCrypt_DRBG_generate(output, state, output_len, (uint8_t*)"", 0);
  EverCrypt_DRBG_uninstantiate(state);
}

// ANCHOR(print_hex_ln)
void
print_hex_ln(size_t bytes_len, uint8_t* bytes)
{
  for (int i = 0; i < bytes_len; ++i) {
    printf("%02x", bytes[i]);
  }

  printf("\n");
}
// ANCHOR_END(print_hex_ln)
