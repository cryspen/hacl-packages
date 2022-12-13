#pragma once

#include <stdint.h>
#include <stdio.h>
#include <vector>

#include "EverCrypt_DRBG.h"
#include "Hacl_K256_ECDSA.h"
#include "Hacl_P256.h"

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

// Only used in examples. Do not use otherwise.
void
generate_sha2_256_hmac_key(uint8_t* key)
{
  bytes key_bytes =
    from_hex("DEE30A3A53F4E25AB8BD47A90A05F4991794FA3C05CBD098F4E03CCB5401A4BD4"
             "71EF4396A5B36B3FCB0A448E82DDC23D8E48DF29DF945E3C0036311138F362B");
  std::copy(key_bytes.begin(), key_bytes.end(), key);
}

// Only used in examples. Do not use otherwise.
void
generate_k256_keypair(uint8_t* sk, uint8_t* pk)
{
  bytes sk_bytes = from_hex(
    "e7e246fd665cb0a1827e09c0fc1204b8f4b3e6bb6dca52c91c0ffd7dc35e09ee");
  std::copy(sk_bytes.begin(), sk_bytes.end(), sk);

  bytes pk_compressed = from_hex(
    "02bb1622feed26432b905f7ac1347c45c048e327abb58862333714c0a65625b14a");

  bytes pk_bytes(64);
  bool res = Hacl_K256_ECDSA_public_key_compressed_to_raw(pk_bytes.data(),
                                                          pk_compressed.data());
  EXPECT_TRUE(res);

  std::copy(pk_bytes.begin(), pk_bytes.end(), pk);
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

// Only used in examples. Do not use otherwise.
void
generate_p256_keypair(uint8_t* sk, uint8_t* pk)
{
  bytes sk_bytes = from_hex(
    "202a6d0faacf15e8468ee8ce3b1e5a3a4395a28a10a5b03604980e584bcac386");
  std::copy(sk_bytes.begin(), sk_bytes.end(), sk);

  bytes pk_compressed = from_hex(
    "03ed1a25d27f12a0a4d76963f1ebefe56b0fdeb06a68c31b83eb9810a66294808d");

  bytes pk_bytes(64);
  bool res = Hacl_P256_compressed_to_raw(pk_compressed.data(), pk_bytes.data());
  EXPECT_TRUE(res);

  std::copy(pk_bytes.begin(), pk_bytes.end(), pk);
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

// Note: This is used to "hide" keys from examples.
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

// Note: This is used to "hide" keys from examples.
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
