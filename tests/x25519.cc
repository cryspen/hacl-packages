/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "EverCrypt_AutoConfig2.h"
#include "EverCrypt_Curve25519.h"
#include "Hacl_Curve25519_51.h"
#include "config.h"
#include "curve25519_vectors.h"
#include "evercrypt.h"
#include "hacl-cpu-features.h"
#include "util.h"

#define VALE TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64

#if VALE
#include "Hacl_Curve25519_64.h"
#include "Vale.h"
#endif

// ANCHOR(DEFINE)
#define HACL_DH_CURVE25519_SECRETKEY_LEN 32
#define HACL_DH_CURVE25519_PUBLICKEY_LEN 32
#define HACL_DH_CURVE25519_SHARED_LEN 32
// ANCHOR_END(DEFINE)

using json = nlohmann::json;
using namespace std;

TEST(x25519Test, HaclTest)
{
  // Initialize CPU feature detection
  hacl_init_cpu_features();
  EverCrypt_AutoConfig2_init();

  for (int i = 0; i < sizeof(vectors) / sizeof(curve25519_test_vector); ++i) {
    uint8_t comp[32] = { 0 };
    Hacl_Curve25519_51_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
    EXPECT_TRUE(compare_and_print(32, comp, vectors[i].secret));

#if VALE
    // We have vale compiled. But we have to check that we can actually use it
    // when calling HACL functions.
    if (vale_x25519_support()) {
      memset(comp, 0, 32);
      Hacl_Curve25519_64_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
      EXPECT_TRUE(compare_and_print(32, comp, vectors[i].secret));
    } else {
      printf(" ! Vale is available but ADX and/or BMI2 extensions are "
             "missing.\n");
    }
#endif
  }
}

// -----------------------------------------------------------------------------

TEST(ApiSuite, ApiTest)
{
  // ANCHOR(EXAMPLE)
  // Alice and Bob want to agree on a shared secret via X25519.

  // Thus, Alice needs a secret and public key ...
  uint8_t alice_sk[HACL_DH_CURVE25519_SECRETKEY_LEN];
  uint8_t alice_pk[HACL_DH_CURVE25519_PUBLICKEY_LEN];
  // Note: This function is not in HACL*.
  //       You need to bring your own random.
  generate_random(alice_sk, HACL_DH_CURVE25519_SECRETKEY_LEN);
  Hacl_Curve25519_51_secret_to_public(alice_pk, alice_sk);

  // ... and Bob does as well.
  uint8_t bob_sk[HACL_DH_CURVE25519_SECRETKEY_LEN];
  uint8_t bob_pk[HACL_DH_CURVE25519_PUBLICKEY_LEN];
  // Note: This function is not in HACL*.
  //       You need to bring your own random.
  generate_random(bob_sk, HACL_DH_CURVE25519_SECRETKEY_LEN);
  Hacl_Curve25519_51_secret_to_public(bob_pk, bob_sk);

  // Now, Alice and Bob exchange their public keys so that
  // Alice can compute her shared secret as ...
  uint8_t shared_alice[HACL_DH_CURVE25519_SHARED_LEN];
  bool res_alice = Hacl_Curve25519_51_ecdh(shared_alice, alice_sk, bob_pk);

  // ... and Bob can compute his shared secret as ...
  uint8_t shared_bob[HACL_DH_CURVE25519_SHARED_LEN];
  bool res_bob = Hacl_Curve25519_51_ecdh(shared_bob, bob_sk, alice_pk);

  // Now, both Alice and Bob should share the same secret value, i.e.,
  //
  //     `shared_alice` == `shared_bob`
  //
  // ... and can use this to derive, e.g., an encryption key.
  // ANCHOR_END(EXAMPLE)

  EXPECT_TRUE(memcmp(shared_alice, shared_bob, HACL_DH_CURVE25519_SHARED_LEN) ==
              0);
  EXPECT_TRUE(res_alice);
  EXPECT_TRUE(res_bob);
}

//=== Wycheproof tests ====

class TestCase
{
public:
  uint32_t tcId;
  bytes public_key;
  bytes private_key;
  bytes shared;
  bool valid;
  bool LowOrderPublic;
  bool NonCanonicalPublic;
  bool SmallPublicKey;
  bool Twist;
  bool ZeroSharedSecret;
};

ostream&
operator<<(ostream& os, const TestCase& test)
{
  os << "TestCase {" << endl
     << "\t.tcId = " << test.tcId << "," << endl
     << "\t.public_key = " << bytes_to_hex(test.public_key) << "," << endl
     << "\t.private_key = " << bytes_to_hex(test.private_key) << "," << endl
     << "\t.shared = " << bytes_to_hex(test.shared) << "," << endl
     << "\t.valid = " << test.valid << "," << endl
     << "\t.LowOrderPublic = " << test.LowOrderPublic << "," << endl
     << "\t.NonCanonicalPublic = " << test.NonCanonicalPublic << "," << endl
     << "\t.SmallPublicKey = " << test.SmallPublicKey << "," << endl
     << "\t.Twist = " << test.Twist << "," << endl
     << "\t.ZeroSharedSecret = " << test.ZeroSharedSecret << "," << endl
     << "}" << endl;
  return os;
}

vector<TestCase>
read_json(string path)
{
  ifstream json_test_file(path);
  json tests_raw;
  json_test_file >> tests_raw;

  vector<TestCase> tests_out;

  // Read test group
  for (auto& group_raw : tests_raw["testGroups"].items()) {
    auto group = group_raw.value();

    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();

      uint32_t tcId = test["tcId"];
      auto private_key = from_hex(test["private"]);
      auto public_key = from_hex(test["public"]);
      auto shared = from_hex(test["shared"]);
      auto result = test["result"];
      bool valid = result == "valid" || result == "acceptable";

      // Flags ...
      bool LowOrderPublic = false;
      bool NonCanonicalPublic = false;
      bool SmallPublicKey = false;
      bool Twist = false;
      bool ZeroSharedSecret = false;

      for (auto flag_raw : test["flags"].items()) {
        string flag = flag_raw.value();

        if (flag == "LowOrderPublic") {
          LowOrderPublic = true;
        }
        if (flag == "NonCanonicalPublic") {
          NonCanonicalPublic = true;
        }
        if (flag == "SmallPublicKey") {
          SmallPublicKey = true;
        }
        if (flag == "Twist") {
          Twist = true;
        }
        if (flag == "ZeroSharedSecret") {
          ZeroSharedSecret = true;
        }
      }

      tests_out.push_back(TestCase{ .tcId = tcId,
                                    .public_key = public_key,
                                    .private_key = private_key,
                                    .shared = shared,
                                    .valid = valid,
                                    .LowOrderPublic = LowOrderPublic,
                                    .NonCanonicalPublic = NonCanonicalPublic,
                                    .SmallPublicKey = SmallPublicKey,
                                    .Twist = Twist,
                                    .ZeroSharedSecret = ZeroSharedSecret });
    }
  }

  return tests_out;
}

class X25519Wycheproof : public ::testing::TestWithParam<TestCase>
{};

TEST_P(X25519Wycheproof, TryWycheproof)
{
  auto test = GetParam();

  bytes got_shared(32, 0);
  bool res = Hacl_Curve25519_51_ecdh(
    got_shared.data(), test.private_key.data(), test.public_key.data());

  if (test.valid) {
    // If the computed shared secret is an array of all zeroes, then the
    // function ecdh returns false to indicate that the operation failed.
    // Otherwise, it returns true.
    if (!test.ZeroSharedSecret) {
      EXPECT_TRUE(res);
    }
    EXPECT_EQ(got_shared, test.shared);
  } else {
    EXPECT_NE(got_shared, test.shared);
  }
}

// ----- EverCrypt -------------------------------------------------------------

typedef EverCryptSuite<TestCase> EverCryptCurve25519;

TEST(EverCryptCurve25519, SecretToPublic)
{
  vector<tuple<bytes, bytes>> tests = {
    make_tuple(
      from_hex(
        "c8c15d1fdb88359660950e82475a7146a49a32d051fcf6344d6df2f6b141a15d"),
      from_hex(
        "b2960014ef49f8a2600826857eeb7d6533eec9b40d49c88f160f6f64398c8a47")),
    make_tuple(
      from_hex(
        "b04a839cf67ad75253a546aa74b476e2e828c303a492cbd12f1cab3789eec37f"),
      from_hex(
        "be30b19e6142a4b647146472b0a34b9487ef38c3cd10693f5bdcc5cb9fa8872c")),
    make_tuple(
      from_hex(
        "f81597fe6e932307f29a5c727a16feaf36400415eeceb1f98b6deb52e670db43"),
      from_hex(
        "bd3ad9142cfe870975f946ccd77c89359cddb5ada42255e4b0280a1b45525e37")),
    make_tuple(
      from_hex(
        "086941832a48d74ffd8b916e302ecabc42b36d52a6165cdcb4dee3ecbab31940"),
      from_hex(
        "54c3865cf9d46189ffaad9b7726dd86b069f60aee7ecdadc199a8bdde6ce5a59")),
    make_tuple(
      from_hex(
        "680563d12cc6c4b0411109e7d5033a8d41497ce86cdb65838ae4057d74ed9660"),
      from_hex(
        "32600558dcc894235f60a4b12db0a51111e61f823e3f6b2d3eeb0d7c148f9647")),
    make_tuple(
      from_hex(
        "f8503ef217540c625756418481754a458f1acfcae76e78d85ac112b4baa0c666"),
      from_hex(
        "383d93ec7fe3fd62fb4c3bed934f59a596e79a9e12cdccf51f00467600ca392b")),
    make_tuple(
      from_hex(
        "d095682243af2bb969c6245141a2811e7987f0d39acb753e28ccf92cb40ffe58"),
      from_hex(
        "a7ecdc169097ef8767454c1d297826e7cfbfda6601f608c9d4392f7788f83207")),
    make_tuple(
      from_hex(
        "a0dbe73f88107bad20eb9aef7eb2613e976e2100e431ac1ef4200560b5892e4f"),
      from_hex(
        "8cbe9364c61475749ccd288049a475163ab76b79ac8c0afc45e6cf68293fb14c")),
    make_tuple(
      from_hex(
        "c8042e508b42dbb2f44a14371cb0fdb4e8ed898aade04d95ac824adf98bb6b77"),
      from_hex(
        "915f70c47c4615b2c1662fb2d7490e4992c675f9fcba4f92d1d5f8af2059ab41")),
    make_tuple(
      from_hex(
        "089f1c74b324c12ab78e0f686a915e4cdd9338856be23719f0ff1aac85d03567"),
      from_hex(
        "93b91ca6e2d0f51db21e2ffb7807a2b0239b67072c7c0b4e73d125b2be798c3a")),
    make_tuple(
      from_hex(
        "8875ed5d8c2ccfa3f722ba001333771aad9481ea155197ac63b16eb9929be55a"),
      from_hex(
        "fbe6f1e20911975f8f42f239df5d8f45d90ee6926e37eb6334b88dbc5047182f")),
    make_tuple(
      from_hex(
        "90a902c6750af2549bedab01e5a8cfe2d8212782cb98c521c4baea3e89869f46"),
      from_hex(
        "0aae2254b1432fa71c89f87ae3ac93eb5608ea6aa1e72b24bf7fd35f29afd83f")),
    make_tuple(
      from_hex(
        "18a819ac53e2a834cfdce40464d9eae254d437119c72c3af762bbe4ca16d3e6b"),
      from_hex(
        "6e57abf213781d1739824babc8b460bf93d525dd176f0abe5b5ed02ababbe221")),
    make_tuple(
      from_hex(
        "10ab41b64c5da593e66ad367d98dcf0dd73d11cf0d5c9318ad53501293b91842"),
      from_hex(
        "b9a37ef0d3d9fd565b2805c68612e79150a2eab4b38e4a204269103d228cbb2f")),
    make_tuple(
      from_hex(
        "6067ab51f80093e3bf291e29758d8471da29dd75b8635cd4d540c0b6828d8c71"),
      from_hex(
        "5713164ade3931f90884de6d06d0442d4ebe0d5aab9e3597892dade6768bd102")),
    make_tuple(
      from_hex(
        "98fb1ca3f426a2a17443bc5b13bf8ff8318b3f11c34b4325af924d6d64b38560"),
      from_hex(
        "c7a9f9cc86f05b5f408a1c616267d9728fb2fead65edabf69f2ac2935ec53135"))
  };

  for (auto test : tests) {
    bytes sk;
    bytes pk;
    tie(sk, pk) = test;

    bytes got_pk(pk.size());
    EverCrypt_Curve25519_secret_to_public(got_pk.data(), sk.data());

    ASSERT_EQ(pk, got_pk);
  }
}

TEST_P(EverCryptCurve25519, KAT)
{
  EverCryptConfig config;
  TestCase test;
  tie(config, test) = this->GetParam();

  {
    bytes got_shared(32);
    bool res = EverCrypt_Curve25519_ecdh(
      got_shared.data(), test.private_key.data(), test.public_key.data());

    if (test.valid) {
      // If the computed shared secret is an array of all zeroes, then the
      // function ecdh returns false to indicate that the operation failed.
      // Otherwise, it returns true.
      if (!test.ZeroSharedSecret) {
        EXPECT_TRUE(res);
      }

      EXPECT_EQ(test.shared, got_shared);
    } else {
      ASSERT_FALSE(res);
      EXPECT_NE(test.shared, got_shared);
    }
  }

  {
    bytes got_shared(32);
    EverCrypt_Curve25519_scalarmult(
      got_shared.data(), test.private_key.data(), test.public_key.data());

    if (test.valid) {
      EXPECT_EQ(test.shared, got_shared);
    } else {
      EXPECT_NE(test.shared, got_shared);
    }
  }
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(Wycheproof,
                         X25519Wycheproof,
                         ::testing::ValuesIn(read_json("x25519_test.json")));

// ----- EverCrypt -------------------------------------------------------------

vector<EverCryptConfig>
generate_x25519_configs()
{
  vector<EverCryptConfig> configs;

  for (uint32_t i = 0; i < 4; ++i) {
    configs.push_back(EverCryptConfig{
      .disable_adx = (i & 1) != 0,
      .disable_aesni = false,
      .disable_avx = false,
      .disable_avx2 = false,
      .disable_avx512 = false,
      .disable_bmi2 = (i & 2) != 0,
      .disable_movbe = false,
      .disable_pclmulqdq = false,
      .disable_rdrand = false,
      .disable_shaext = false,
      .disable_sse = false,
    });
  }

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  Wycheproof,
  EverCryptCurve25519,
  ::testing::Combine(::testing::ValuesIn(generate_x25519_configs()),
                     ::testing::ValuesIn(read_json("x25519_test.json"))));
