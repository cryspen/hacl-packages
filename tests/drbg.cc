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
#include <tuple>

#include "EverCrypt_AutoConfig2.h"
#include "EverCrypt_DRBG.h"
#include "Hacl_HMAC_DRBG.h"
#include "Hacl_Spec.h"
#include "evercrypt.h"
#include "hacl-cpu-features.h"

#include "util.h"

using namespace std;
using json = nlohmann::json;

class CAVPTestCase
{
public:
  string hash;
  vector<bytes> AdditionalInput;
  bool PredictionResistance;
  vector<bytes> EntropyInputPR;
  uint32_t COUNT;
  bytes EntropyInput;
  bytes Nonce;
  bytes PersonalizationString;
  bytes EntropyInputReseed;
  bytes AdditionalInputReseed;
  bytes ReturnedBits;
};

ostream&
operator<<(ostream& os, const CAVPTestCase& test)
{
  os << "CAVPTestCase {" << endl
     << "\t.hash = " << test.hash << "," << endl
     << "\t.AdditionalInput = [" << endl;
  for (auto ai : test.AdditionalInput) {
    os << "\t\t" << bytes_to_hex(ai) << "," << endl;
  }
  os << "\t]," << endl
     << "\t\t.PredictionResistance = " << test.PredictionResistance << ","
     << endl
     << "\t\t.EntropyInputPR = [" << endl;
  for (auto ei : test.EntropyInputPR) {
    os << "\t\t" << bytes_to_hex(ei) << "," << endl;
  }
  os << "\t]," << endl
     << "\t.COUNT = " << test.COUNT << "," << endl
     << "\t.PersonalizationString = "
     << bytes_to_hex(test.PersonalizationString) << "," << endl
     << "\t.EntropyInputReseed = " << bytes_to_hex(test.EntropyInputReseed)
     << "," << endl
     << "\t.AdditionalInputReseed = "
     << bytes_to_hex(test.AdditionalInputReseed) << "," << endl
     << "\t.ReturnedBits = " << bytes_to_hex(test.ReturnedBits) << "," << endl
     << "}" << endl;
  return os;
}

void
cavp_to_hash(string value,
             bool& skip_out,
             Spec_Hash_Definitions_hash_alg& hash_out)
{
  skip_out = false;

  if (value == "SHA-1") {
    hash_out = Spec_Hash_Definitions_SHA1;
  } else if (value == "SHA-224") {
    skip_out = true;
  } else if (value == "SHA-256") {
    hash_out = Spec_Hash_Definitions_SHA2_256;
  } else if (value == "SHA-384") {
    hash_out = Spec_Hash_Definitions_SHA2_384;
  } else if (value == "SHA-512") {
    hash_out = Spec_Hash_Definitions_SHA2_512;
  } else if (value == "SHA-512/224") {
    skip_out = true;
  } else if (value == "SHA-512/256") {
    skip_out = true;
  } else {
    FAIL() << "Unexpected value \"" << value << "\".";
  }
}

class DrbgSuite : public ::testing::Test
{
  void SetUp() override
  {
    hacl_init_cpu_features();
    EverCrypt_AutoConfig2_init();
  }
};

TEST(DrbgSuite, SmokeTest)
{
  bytes entropy = from_hex("AA");
  bytes nonce = from_hex("AA");
  bytes personalization = from_hex("AA");

  // Possible Instantiations.
  vector<Spec_Hash_Definitions_hash_alg> hashes = {
    Spec_Hash_Definitions_SHA1,
    Spec_Hash_Definitions_SHA2_256,
    Spec_Hash_Definitions_SHA2_384,
    Spec_Hash_Definitions_SHA2_512,
  };

  // Counts.
  vector<Spec_Hash_Definitions_hash_alg> counts = {
    0, 1, 2, 3, 4, 5, 8, 9, 16, 17, 32, 33, 64, 65, 128, 129,
  };

  vector<bytes> additionals = {
    from_hex(""),
    from_hex("AA"),
    from_hex("AAFF"),
    from_hex("AAAAAAAA"),
    from_hex("AAAAAAAAFF"),
    from_hex("AAAAAAAAAAAAAAAA"),
    from_hex("AAAAAAAAAAAAAAAAFF"),
    from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFF"),
  };

  for (auto hash : hashes) {
    for (auto count : counts) {
      for (auto additional : additionals) {
        // Init
        Hacl_HMAC_DRBG_state state = Hacl_HMAC_DRBG_create_in(hash);
        Hacl_HMAC_DRBG_instantiate(hash,
                                   state,
                                   entropy.size(),
                                   entropy.data(),
                                   nonce.size(),
                                   nonce.data(),
                                   personalization.size(),
                                   personalization.data());

        // This is only to cover all functions.
        bool _ = Hacl_HMAC_DRBG_uu___is_State(hash, state);

        // Generate
        bytes output = bytes(count);
        bool res = Hacl_HMAC_DRBG_generate(hash,
                                           output.data(),
                                           state,
                                           count,
                                           additional.size(),
                                           additional.data());

        EXPECT_TRUE(res);
      }
    }
  }
}

TEST(DrbgSuite, MinLengthKAT)
{
  vector<tuple<Spec_Hash_Definitions_hash_alg, uint32_t>> tests = {
    make_tuple(Spec_Hash_Definitions_SHA1, 16),
    make_tuple(Spec_Hash_Definitions_SHA2_256, 32),
    make_tuple(Spec_Hash_Definitions_SHA2_384, 32),
    make_tuple(Spec_Hash_Definitions_SHA2_512, 32),
  };

  for (auto test : tests) {
    Spec_Hash_Definitions_hash_alg alg;
    uint32_t expected_min_length;
    tie(alg, expected_min_length) = test;

    uint32_t got_min_length = Hacl_HMAC_DRBG_min_length(alg);

    ASSERT_EQ(expected_min_length, got_min_length);
  }
}

class DrbgNRSuite : public ::testing::TestWithParam<CAVPTestCase>
{
  void SetUp() override
  {
    hacl_init_cpu_features();
    EverCrypt_AutoConfig2_init();
  }
};

TEST_P(DrbgNRSuite, KAT)
{
  auto test = GetParam();

  bool skip = false;
  Spec_Hash_Definitions_hash_alg hash;
  cavp_to_hash(test.hash, skip, hash);
  if (skip) {
    cout << "Skipping \"" << test.hash << "\"" << endl;
    return;
  }

  // Init
  Hacl_HMAC_DRBG_state state = Hacl_HMAC_DRBG_create_in(hash);
  Hacl_HMAC_DRBG_instantiate(hash,
                             state,
                             test.EntropyInput.size(),
                             test.EntropyInput.data(),
                             test.Nonce.size(),
                             test.Nonce.data(),
                             test.PersonalizationString.size(),
                             test.PersonalizationString.data());

  // Generate
  bytes got_ReturnedBits = bytes(test.ReturnedBits.size());
  for (auto additional : test.AdditionalInput) {
    bool res = Hacl_HMAC_DRBG_generate(hash,
                                       got_ReturnedBits.data(),
                                       state,
                                       got_ReturnedBits.size(),
                                       additional.size(),
                                       additional.data());

    EXPECT_TRUE(res);
  }

  ASSERT_EQ(test.ReturnedBits, got_ReturnedBits);
}

class DrbgPRFalseSuite : public ::testing::TestWithParam<CAVPTestCase>
{
  void SetUp() override
  {
    hacl_init_cpu_features();
    EverCrypt_AutoConfig2_init();
  }
};

TEST_P(DrbgPRFalseSuite, KAT)
{
  auto test = GetParam();

  bool skip = false;
  Spec_Hash_Definitions_hash_alg hash;
  cavp_to_hash(test.hash, skip, hash);
  if (skip) {
    cout << "Skipping \"" << test.hash << "\"" << endl;
    return;
  }

  // Init
  Hacl_HMAC_DRBG_state state = Hacl_HMAC_DRBG_create_in(hash);
  Hacl_HMAC_DRBG_instantiate(hash,
                             state,
                             test.EntropyInput.size(),
                             test.EntropyInput.data(),
                             test.Nonce.size(),
                             test.Nonce.data(),
                             test.PersonalizationString.size(),
                             test.PersonalizationString.data());

  // Generate
  Hacl_HMAC_DRBG_reseed(hash,
                        state,
                        test.EntropyInputReseed.size(),
                        test.EntropyInputReseed.data(),
                        test.AdditionalInputReseed.size(),
                        test.AdditionalInputReseed.data());

  bytes got_ReturnedBits = bytes(test.ReturnedBits.size());
  for (auto additional : test.AdditionalInput) {
    bool res = Hacl_HMAC_DRBG_generate(hash,
                                       got_ReturnedBits.data(),
                                       state,
                                       got_ReturnedBits.size(),
                                       additional.size(),
                                       additional.data());

    EXPECT_TRUE(res);
  }

  ASSERT_EQ(test.ReturnedBits, got_ReturnedBits);
}

class DrbgPRTrueSuite : public ::testing::TestWithParam<CAVPTestCase>
{
  void SetUp() override
  {
    hacl_init_cpu_features();
    EverCrypt_AutoConfig2_init();
  }
};

TEST_P(DrbgPRTrueSuite, KAT)
{
  auto test = GetParam();

  bool skip = false;
  Spec_Hash_Definitions_hash_alg hash;
  cavp_to_hash(test.hash, skip, hash);
  if (skip) {
    cout << "Skipping \"" << test.hash << "\"" << endl;
    return;
  }

  // TODO: Does it provide predictive resistance?
}

// ----- EverCrypt -------------------------------------------------------------

typedef EverCryptSuite<CAVPTestCase> DrbgNRSuiteEverCrypt;

TEST_P(DrbgNRSuiteEverCrypt, KAT)
{
  EverCryptConfig config;
  CAVPTestCase test;
  tie(config, test) = this->GetParam();

  bool skip = false;
  Spec_Hash_Definitions_hash_alg hash;
  cavp_to_hash(test.hash, skip, hash);
  if (skip) {
    cout << "Skipping \"" << test.hash << "\"" << endl;
    return;
  }

  // Init
  EverCrypt_DRBG_state_s* state = EverCrypt_DRBG_create(hash);
  bool res = EverCrypt_DRBG_instantiate(state,
                                        test.PersonalizationString.data(),
                                        test.PersonalizationString.size());
  ASSERT_TRUE(res);

  // FIXME: EntropyInput?

  // Generate
  bytes got_ReturnedBits = bytes(test.ReturnedBits.size());
  for (auto additional : test.AdditionalInput) {
    bool res = EverCrypt_DRBG_generate(got_ReturnedBits.data(),
                                       state,
                                       got_ReturnedBits.size(),
                                       additional.data(),
                                       additional.size());

    EXPECT_TRUE(res);
  }

  // Finish
  EverCrypt_DRBG_uninstantiate(state);

  ASSERT_EQ(test.ReturnedBits, got_ReturnedBits);
}

typedef EverCryptSuite<CAVPTestCase> DrbgPRFalseSuiteEverCrypt;

TEST_P(DrbgPRFalseSuiteEverCrypt, KAT)
{
  EverCryptConfig config;
  CAVPTestCase test;
  tie(config, test) = this->GetParam();

  bool skip = false;
  Spec_Hash_Definitions_hash_alg hash;
  cavp_to_hash(test.hash, skip, hash);
  if (skip) {
    cout << "Skipping \"" << test.hash << "\"" << endl;
    return;
  }

  // Init
  EverCrypt_DRBG_state_s* state = EverCrypt_DRBG_create(hash);
  bool res = EverCrypt_DRBG_instantiate(state,
                                        test.PersonalizationString.data(),
                                        test.PersonalizationString.size());
  EXPECT_TRUE(res);

  // FIXME: EntropyInput?

  // Reseed
  res = EverCrypt_DRBG_reseed(state,
                              test.AdditionalInputReseed.data(),
                              test.AdditionalInputReseed.size());
  EXPECT_TRUE(res);

  // Generate
  bytes got_ReturnedBits = bytes(test.ReturnedBits.size());
  for (auto additional : test.AdditionalInput) {
    res = EverCrypt_DRBG_generate(got_ReturnedBits.data(),
                                  state,
                                  got_ReturnedBits.size(),
                                  additional.data(),
                                  additional.size());
    EXPECT_TRUE(res);
  }

  // Finish
  EverCrypt_DRBG_uninstantiate(state);

  ASSERT_EQ(test.ReturnedBits, got_ReturnedBits);
}

typedef EverCryptSuite<CAVPTestCase> DrbgPRTrueSuiteEverCrypt;

TEST_P(DrbgPRTrueSuiteEverCrypt, KAT)
{
  EverCryptConfig config;
  CAVPTestCase test;
  tie(config, test) = this->GetParam();

  bool skip = false;
  Spec_Hash_Definitions_hash_alg hash;
  cavp_to_hash(test.hash, skip, hash);
  if (skip) {
    cout << "Skipping \"" << test.hash << "\"" << endl;
    return;
  }

  // Init
  EverCrypt_DRBG_state_s* state = EverCrypt_DRBG_create(hash);
  bool res = EverCrypt_DRBG_instantiate(state,
                                        test.PersonalizationString.data(),
                                        test.PersonalizationString.size());

  // Generate
  // TODO: Does it provide prediction resistance?

  // Finish
  EverCrypt_DRBG_uninstantiate(state);
}

// -----------------------------------------------------------------------------

vector<CAVPTestCase>
read_json_cavp(string path)
{
  json tests_raw;
  ifstream file(path);
  file >> tests_raw;

  vector<CAVPTestCase> tests;

  for (auto& test_raw : tests_raw.items()) {
    auto test = test_raw.value();

    string hash = test["hash"];
    vector<bytes> AdditionalInput = vector<bytes>();
    for (auto ai_raw : test["AdditionalInput"].items()) {
      string ai = ai_raw.value();
      AdditionalInput.push_back(from_hex(ai));
    }
    bool PredictionResistance;
    if (test.contains("PredictionResistance")) {
      PredictionResistance = test["PredictionResistance"];
    } else {
      PredictionResistance = false;
    }
    vector<bytes> EntropyInputPR;
    if (test.contains("EntropyInputPR")) {
      for (auto ei_raw : test["EntropyInputPR"].items()) {
        string ei = ei_raw.value();
        EntropyInputPR.push_back(from_hex(ei));
      }
    }
    auto COUNT = test["COUNT"];
    auto EntropyInput = from_hex(test["EntropyInput"]);
    auto Nonce = from_hex(test["Nonce"]);
    auto PersonalizationString = from_hex(test["PersonalizationString"]);
    bytes EntropyInputReseed;
    if (test.contains("EntropyInputReseed")) {
      EntropyInputReseed = from_hex(test["EntropyInputReseed"]);
    }
    bytes AdditionalInputReseed;
    if (test.contains("AdditionalInputReseed")) {
      AdditionalInputReseed = from_hex(test["AdditionalInputReseed"]);
    }
    auto ReturnedBits = from_hex(test["ReturnedBits"]);

    tests.push_back(CAVPTestCase{
      .hash = hash,
      .AdditionalInput = AdditionalInput,
      .PredictionResistance = PredictionResistance,
      .EntropyInputPR = EntropyInputPR,
      .COUNT = COUNT,
      .EntropyInput = EntropyInput,
      .Nonce = Nonce,
      .PersonalizationString = PersonalizationString,
      .EntropyInputReseed = EntropyInputReseed,
      .AdditionalInputReseed = AdditionalInputReseed,
      .ReturnedBits = ReturnedBits,
    });
  }

  return tests;
}

// -----------------------------------------------------------------------------

INSTANTIATE_TEST_SUITE_P(
  CAVPNoReseed,
  DrbgNRSuite,
  ::testing::ValuesIn(read_json_cavp("DRBG_CAVP_no_reseed.json")));

INSTANTIATE_TEST_SUITE_P(
  CAVPPrFalse,
  DrbgPRFalseSuite,
  ::testing::ValuesIn(read_json_cavp("DRBG_CAVP_pr_false.json")));

INSTANTIATE_TEST_SUITE_P(
  CAVPPrTrue,
  DrbgPRTrueSuite,
  ::testing::ValuesIn(read_json_cavp("DRBG_CAVP_pr_true.json")));

// ----- EverCrypt -------------------------------------------------------------

vector<EverCryptConfig>
generate_drbg_configs()
{
  vector<EverCryptConfig> configs;

  configs.push_back(EverCryptConfig{
    .disable_adx = false,
    .disable_aesni = false,
    .disable_avx = false,
    .disable_avx2 = false,
    .disable_avx512 = false,
    .disable_bmi2 = false,
    .disable_movbe = false,
    .disable_pclmulqdq = false,
    .disable_rdrand = false,
    .disable_shaext = false,
    .disable_sse = false,
  });

  return configs;
}

INSTANTIATE_TEST_SUITE_P(
  CAVPNoReseed,
  DrbgNRSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_drbg_configs()),
    ::testing::ValuesIn(read_json_cavp("DRBG_CAVP_no_reseed.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPShort,
  DrbgPRFalseSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_drbg_configs()),
    ::testing::ValuesIn(read_json_cavp("DRBG_CAVP_pr_false.json"))));

INSTANTIATE_TEST_SUITE_P(
  Sha1CAVPLong,
  DrbgPRTrueSuiteEverCrypt,
  ::testing::Combine(
    ::testing::ValuesIn(generate_drbg_configs()),
    ::testing::ValuesIn(read_json_cavp("DRBG_CAVP_pr_true.json"))));
