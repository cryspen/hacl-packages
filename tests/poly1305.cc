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

#include "EverCrypt_Poly1305.h"
#include "Hacl_MAC_Poly1305.h"
#include "hacl-cpu-features.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_MAC_Poly1305_Simd128.h"
#endif

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_MAC_Poly1305_Simd256.h"
#endif

using json = nlohmann::json;
using namespace std;

class TestCase
{
public:
  string comment;
  bytes key;
  bytes text;
  bytes tag;
};

ostream&
operator<<(ostream& os, const TestCase& test)
{
  os << "TestCase {" << endl
     << "\t.comment = " << test.comment << endl
     << "\t.key = " << bytes_to_hex(test.key) << endl
     << "\t.text = " << bytes_to_hex(test.text) << endl
     << "\t.tag = " << bytes_to_hex(test.tag) << endl
     << "}" << endl;
  return os;
}

// -----------------------------------------------------------------------------

const uint32_t POLY1305_KEY_SIZE = 32;
const uint32_t POLY1305_TAG_SIZE = 16;

void
poly1305_mac(bytes key, bytes text, bytes& tag)
{
  cout << "Poly1305.Mac" << endl;

  // This works everywhere. Let's use it as a base for comparisons.
  bytes base_tag = vector<uint8_t>(POLY1305_TAG_SIZE);
  Hacl_MAC_Poly1305_mac(base_tag.data(), text.data(), text.size(), key.data());

#ifdef HACL_CAN_COMPILE_VEC128
  if (hacl_vec128_support()) {
    cout << "Poly1305.Mac (VEC128)" << endl;

    bytes tag = vector<uint8_t>(POLY1305_TAG_SIZE);
    Hacl_MAC_Poly1305_Simd128_mac(
      tag.data(), text.data(), text.size(), key.data());

    EXPECT_EQ(base_tag, tag)
      << "Detected difference between base and _128 version";
  } else {
    cout << "No support for VEC128 on this CPU." << endl;
  }
#endif

#ifdef HACL_CAN_COMPILE_VEC256
  if (hacl_vec256_support()) {
    cout << "Poly1305.Mac (VEC256)" << endl;

    bytes tag = vector<uint8_t>(POLY1305_TAG_SIZE);
    Hacl_MAC_Poly1305_Simd256_mac(
      tag.data(), text.data(), text.size(), key.data());

    EXPECT_EQ(base_tag, tag)
      << "Detected difference between base and _256 version";
  } else {
    cout << "No support for VEC256 on this CPU." << endl;
  }
#endif

  // EverCrypt
  {
    cout << "Poly1305.Mac (EverCrypt)" << endl;

    EverCrypt_AutoConfig2_init();

    bytes tag = bytes(POLY1305_TAG_SIZE);

    EverCrypt_Poly1305_mac(
      tag.data(), text.data(), text.size(), key.data());

    EXPECT_EQ(base_tag, tag)
      << "Detected difference between base and EverCrypt version";
  }

  tag = base_tag;
}

void
poly1305_mac_streaming(bytes key,
                       bytes text,
                       vector<size_t> lengths,
                       bytes expected_tag)
{
  cout << "Poly1305.Mac (Streaming)" << endl;
  {
    bytes got_tag = vector<uint8_t>(POLY1305_TAG_SIZE);

    // Init
    uint8_t raw_state[32];
    Hacl_MAC_Poly1305_state_t* state = Hacl_MAC_Poly1305_malloc(raw_state);
    Hacl_MAC_Poly1305_reset(state, key.data());

    // Update
    for (auto chunk : split_by_index_list(text, lengths)) {
      Hacl_MAC_Poly1305_update(state, chunk.data(), chunk.size());
    }

    // Finish
    Hacl_MAC_Poly1305_digest(state, got_tag.data());
    Hacl_MAC_Poly1305_free(state);

    ASSERT_EQ(expected_tag, got_tag);
  }

#ifdef HACL_CAN_COMPILE_VEC128
  if (hacl_vec128_support()) {
    cout << "Poly1305.Mac (VEC128, Streaming)" << endl;
    {
      bytes got_tag = vector<uint8_t>(POLY1305_TAG_SIZE);

      // Init
      Hacl_MAC_Poly1305_Simd128_state_t* state =
        Hacl_MAC_Poly1305_Simd128_malloc(key.data());
      Hacl_MAC_Poly1305_Simd128_reset(state, key.data());

      // Update
      for (auto chunk : split_by_index_list(text, lengths)) {
        Hacl_MAC_Poly1305_Simd128_update(state, chunk.data(), chunk.size());
      }

      // Finish
      Hacl_MAC_Poly1305_Simd128_digest(state, got_tag.data());
      Hacl_MAC_Poly1305_Simd128_free(state);

      ASSERT_EQ(expected_tag, got_tag);
    }
  } else {
    cout << "No support for VEC128 on this CPU." << endl;
  }
#endif

#ifdef HACL_CAN_COMPILE_VEC256
  if (hacl_vec256_support()) {
    cout << "Poly1305.Mac (VEC256, Streaming)" << endl;
    {
      bytes tag = vector<uint8_t>(POLY1305_TAG_SIZE);
      
      // Init
      Hacl_MAC_Poly1305_Simd256_state_t* state =
        Hacl_MAC_Poly1305_Simd256_malloc(key.data());
      
      // Update
      for (auto chunk : split_by_index_list(text, lengths)) {
        Hacl_MAC_Poly1305_Simd256_update(state, chunk.data(), chunk.size());
      }
      
      // Finish
      Hacl_MAC_Poly1305_Simd256_digest(state, tag.data());
      Hacl_MAC_Poly1305_Simd256_free(state);
      
      EXPECT_EQ(expected_tag, tag)
        << "Detected difference between _32 and _128 version";
    }
  } else {
    cout << "No support for VEC256 on this CPU." << endl;
  }
#endif
}

class Poly1305Suite
  : public ::testing::TestWithParam<tuple<TestCase, vector<size_t>>>
{};

TEST_P(Poly1305Suite, KAT)
{
  // This must be called before `hacl_vec{128,256}_support()`.
  hacl_init_cpu_features();

  TestCase test;
  vector<size_t> lengths;
  tie(test, lengths) = GetParam();

  // Test API
  {
    bytes got_tag = vector<uint8_t>(POLY1305_TAG_SIZE);
    poly1305_mac(test.key, test.text, got_tag);

    EXPECT_EQ(test.tag, got_tag);
  }

  // Test Streaming API
  {
    poly1305_mac_streaming(test.key, test.text, lengths, test.tag);
  }
}

vector<TestCase>
read_json(string path)
{
  json raw_tests;
  ifstream file(path);
  file >> raw_tests;

  vector<TestCase> tests;

  for (auto& test_raw : raw_tests.items()) {
    auto test = test_raw.value();

    string comment = test["comment"];
    bytes tag = from_hex(test["tag"]);

    if (test.contains("key")) {
      bytes key = from_hex(test["key"]);
      bytes text = from_hex(test["text"]);

      tests.push_back(TestCase{
        .comment = comment,
        .key = key,
        .text = text,
        .tag = tag,
      });
    } else {
      bytes text = from_hex(test["data"]);
      bytes key_1 = from_hex(test["R"]);
      bytes key_2 = from_hex(test["S"]);
      key_1.reserve(key_1.size() + key_2.size());
      key_1.insert(key_1.end(), key_2.begin(), key_2.end());
      bytes key = key_1;

      tests.push_back(TestCase{
        .comment = comment,
        .key = key,
        .text = text,
        .tag = tag,
      });
    }
  }

  return tests;
}

INSTANTIATE_TEST_SUITE_P(
  Poly1305RFC8439,
  Poly1305Suite,
  ::testing::Combine(::testing::ValuesIn(read_json("poly1305_rfc8439.json")),
                     ::testing::ValuesIn(make_lengths())));
