/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Hacl_Hash_SHA2.h"
#include "Hacl_K256_ECDSA.h"
#include "util.h"

// ANCHOR(EXAMPLE DEFINE)
// Note: HACL Packages will provide these in a later version.
#define HACL_SIGNATURE_ECDSA_K256_SECRETKEY_LEN 32

#define HACL_SIGNATURE_ECDSA_K256_PUBLICKEY_LEN 64
#define HACL_SIGNATURE_ECDSA_K256_PUBLICKEY_COMPRESSED_LEN 33
#define HACL_SIGNATURE_ECDSA_K256_PUBLICKEY_UNCOMPRESSED_LEN 65

#define HACL_SIGNATURE_ECDSA_K256_NONCE_LEN 32

#define HACL_SIGNATURE_ECDSA_K256_SIGNATURE_LEN 64
// ANCHOR_END(EXAMPLE DEFINE)

using json = nlohmann::json;
using namespace std;

TEST(ApiSuite, ApiTest)
{
  // ANCHOR(EXAMPLE)
  // We want to sign and verify a message.

  // Message
  const char* message = "Hello, World!";
  uint32_t message_size = strlen(message);

  // Keys
  uint8_t sk[HACL_SIGNATURE_ECDSA_K256_SECRETKEY_LEN];
  uint8_t pk[HACL_SIGNATURE_ECDSA_K256_PUBLICKEY_LEN];

  // Note: This function is not in HACL*.
  //       You need to bring your own keys.
  generate_k256_keypair(sk, pk);

  // Nonce
  uint8_t nonce[HACL_SIGNATURE_ECDSA_K256_NONCE_LEN];

  // Signature
  uint8_t signature[HACL_SIGNATURE_ECDSA_K256_SIGNATURE_LEN];

  // Sign
  bool res_sign = Hacl_K256_ECDSA_ecdsa_sign_sha256(
    signature, message_size, (uint8_t*)message, sk, nonce);

  if (!res_sign) {
    // Error
  }

  // Verify
  bool res_verify = Hacl_K256_ECDSA_ecdsa_verify_sha256(
    message_size, (uint8_t*)message, pk, signature);

  if (!res_verify) {
    // Error
  }
  // ANCHOR_END(EXAMPLE)

  EXPECT_TRUE(res_sign);
  EXPECT_TRUE(res_verify);
}

class TestCase
{
public:
  bytes public_key;
  bytes msg;
  bytes sig;
  bool valid;
};

ostream&
operator<<(ostream& os, const TestCase& test)
{
  os << "TestCase {" << endl
     << "\t.public_key = " << bytes_to_hex(test.public_key) << endl
     << "\t.msg = " << bytes_to_hex(test.msg) << endl
     << "\t.sig = " << bytes_to_hex(test.sig) << endl
     << "\t.valid = " << test.valid << endl
     << "}" << endl;
  return os;
}

// -----------------------------------------------------------------------------

class P256EcdsaWycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(P256EcdsaWycheproof, TryWycheproof)
{
  const TestCase& test_case(GetParam());

  //   printf("pk: %s\n", bytes_to_hex(test_case.public_key).c_str());
  //   printf("msg: %s\n", bytes_to_hex(test_case.msg).c_str());
  // Stupid const
  uint8_t* public_key = const_cast<uint8_t*>(test_case.public_key.data());
  uint8_t* msg = const_cast<uint8_t*>(test_case.msg.data());

  // Convert public key first
  uint8_t plain_public_key[64] = { 0 };
  bool uncompressed_point = false;
  bool compressed_point = false;
  if (test_case.public_key.size() >= 65) {
    uncompressed_point = Hacl_K256_ECDSA_public_key_uncompressed_to_raw(
      plain_public_key, public_key);
  }
  if (!uncompressed_point && test_case.public_key.size() >= 32) {
    compressed_point = Hacl_K256_ECDSA_public_key_compressed_to_raw(
      plain_public_key, public_key);
  }
  EXPECT_TRUE(uncompressed_point || compressed_point || !test_case.valid);

  // Parse DER signature.
  // FIXME: This should really be in the HACL* libraray.
  //        The parsing here is opportunistic and not robust.
  size_t sig_pointer = 0;
  if (test_case.valid) {
    EXPECT_TRUE(test_case.sig.size() >= 2);
  }
  bytes r, s;

  if (test_case.sig.size() > 2) {
    if (test_case.valid) {
      size_t pos = 0;
      EXPECT_EQ(test_case.sig[pos++], 0x30); // Sequence tag
      auto der_length = test_case.sig[pos++];
      EXPECT_FALSE(der_length & 0x80);
      EXPECT_EQ(test_case.sig[pos++], 0x02); // Integer
      auto x_length = test_case.sig[pos++];
      r = bytes(&test_case.sig[pos], &test_case.sig[pos] + x_length);
      pos += x_length;
      EXPECT_EQ(test_case.sig[pos++], 0x02); // Integer
      auto y_length = test_case.sig[pos++];
      s = bytes(&test_case.sig[pos], &test_case.sig[pos] + y_length);
      pos += y_length;
      EXPECT_EQ(pos, der_length + 2);
    }
  }
  if (r.size() != 0 && s.size() != 0) {
    // Removing leading 0s and make r and s 32 bytes each
    while (r[0] == 0x00) {
      r.erase(r.begin());
    }
    while (r.size() < 32) {
      r.insert(r.begin(), 0);
    }
    while (s[0] == 0x00) {
      s.erase(s.begin());
    }
    while (s.size() < 32) {
      s.insert(s.begin(), 0);
    }
    EXPECT_EQ(32, r.size());
    EXPECT_EQ(32, s.size());

    // Concat r||s because the API is awesome.
    bytes rs;
    rs.insert(rs.end(), r.begin(), r.end());
    rs.insert(rs.end(), s.begin(), s.end());

    // TODO: Only testing non low-S normalized here for now.
    uint8_t digest[32] = { 0 };
    Hacl_Streaming_SHA2_hash_256(msg, test_case.msg.size(), &digest[0]);
    EXPECT_EQ(test_case.valid,
              Hacl_K256_ECDSA_ecdsa_verify_hashed_msg(
                &digest[0], plain_public_key, rs.data()));
  }
}

class K256Ecdsa
{};

TEST(K256Ecdsa, SelfTest)
{
  bytes sk = from_hex(
    "a32aa1699dcaf84c231dc805981942aa8793b4256d6a21de3e78c9036d39cc1f");
  bytes pk_compressed = from_hex(
    "029d2ad65c5ef50e1651d78825dae280499155f5053def90487fc0282de763a49d");
  bytes pk_uncompressed = from_hex(
    "049d2ad65c5ef50e1651d78825dae280499155f5053def90487fc0282de763a49"
    "dad99718541ecbae69bcc43a74fb27462f5ed6e5a0d722f95cd8b685b7f8d26ea");

  // Compressed-to-raw and vice versa.
  {
    bytes got_pk_raw(64);
    bool res = Hacl_K256_ECDSA_public_key_compressed_to_raw(
      got_pk_raw.data(), pk_compressed.data());
    EXPECT_TRUE(res);

    bytes got_pk_compressed = bytes(1 + 32);
    Hacl_K256_ECDSA_public_key_compressed_from_raw(got_pk_compressed.data(),
                                                   got_pk_raw.data());

    ASSERT_EQ(pk_compressed, got_pk_compressed);
  }

  // Uncompressed-to-raw and vice versa.
  {
    bytes got_pk_raw(64);
    bool res = Hacl_K256_ECDSA_public_key_uncompressed_to_raw(
      got_pk_raw.data(), pk_uncompressed.data());
    EXPECT_TRUE(res);

    bytes got_pk_uncompressed = bytes(1 + 64);
    Hacl_K256_ECDSA_public_key_uncompressed_from_raw(got_pk_uncompressed.data(),
                                                     got_pk_raw.data());

    ASSERT_EQ(pk_uncompressed, got_pk_uncompressed);
  }

  bytes pk(64);
  bool res = Hacl_K256_ECDSA_public_key_compressed_to_raw(pk.data(),
                                                          pk_compressed.data());
  EXPECT_TRUE(res);

  std::vector<bytes> msgs = {
    from_hex(""),
    from_hex("FF"),
    from_hex("AA"),
    from_hex("AAFF"),
    from_hex("AAAA"),
    from_hex("AAAAFF"),
    from_hex("AAAAAAAA"),
    from_hex("AAAAAAAAFF"),
    from_hex("AAAAAAAAAAAAAAAA"),
    from_hex("AAAAAAAAAAAAAAAAFF"),
    from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFF"),
    from_hex(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    from_hex(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFF"),
  };

  typedef bool (*sign_fn)(uint8_t*, uint32_t, uint8_t*, uint8_t*, uint8_t*);
  typedef bool (*verify_fn)(uint32_t, uint8_t*, uint8_t*, uint8_t*);

  std::vector<std::tuple<std::string, sign_fn, verify_fn>> algs = {
    std::make_tuple("secp256k1_sha256",
                    Hacl_K256_ECDSA_secp256k1_ecdsa_sign_sha256,
                    Hacl_K256_ECDSA_secp256k1_ecdsa_verify_sha256),
    std::make_tuple("sha256",
                    Hacl_K256_ECDSA_ecdsa_sign_sha256,
                    Hacl_K256_ECDSA_ecdsa_verify_sha256)
  };

  // Note: 1 <= nonce < q
  bytes nonce = bytes(32, 'A');

  for (auto alg : algs) {
    std::string name;
    sign_fn sign;
    verify_fn verify;
    std::tie(name, sign, verify) = alg;

    for (auto msg : msgs) {
      bytes got_signature(64);
      bool res = sign(
        got_signature.data(), msg.size(), msg.data(), sk.data(), nonce.data());
      ASSERT_TRUE(res);

      res = verify(msg.size(), msg.data(), pk.data(), got_signature.data());
      ASSERT_TRUE(res);
    }
  }
}

// -----------------------------------------------------------------------------

std::vector<TestCase>
read_json()
{

  // Read JSON test vector
  std::string test_dir = "ecdsa_secp256k1_sha256_test.json";
  std::ifstream json_test_file(test_dir);
  json test_vectors;
  json_test_file >> test_vectors;

  std::vector<TestCase> tests_out;

  // Read test group
  for (auto& test : test_vectors["testGroups"].items()) {
    auto test_value = test.value();

    // Read the key
    auto key = test_value["key"];
    auto public_key = from_hex(key["uncompressed"]);

    auto tests = test_value["tests"];
    for (auto& test_case : tests.items()) {
      auto test_case_value = test_case.value();
      auto msg = from_hex(test_case_value["msg"]);
      auto sig = from_hex(test_case_value["sig"]);
      auto result = test_case_value["result"];
      bool valid = result == "valid" || result == "acceptable";

      tests_out.push_back({ public_key, msg, sig, valid });
    }
  }

  return tests_out;
}

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         P256EcdsaWycheproof,
                         ::testing::ValuesIn(read_json()));
