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

#include "hacl-cpu-features.h"
#include "util.h"

#include "Hacl_Poly1305_32.h"
#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Poly1305_128.h"
#include "Hacl_Streaming_Poly1305_128.h"
#endif
#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Poly1305_256.h"
#include "Hacl_Streaming_Poly1305_256.h"
#endif

using json = nlohmann::json;

typedef struct
{
  std::string comment;
  bytes key;
  bytes text;
  bytes tag;
  //  std::vector<bytes> m;
  //  std::vector<bytes> c;
  //  bytes r;
  //  bytes mr;
  //  bytes k;
  //  bytes n;
  //  bytes AESkn;
  //  bytes mac;
} TestCase;

// -----------------------------------------------------------------------------

const uint32_t POLY1305_KEY_SIZE = 32;
const uint32_t POLY1305_TAG_SIZE = 16;

// Poly1305 is a one-time authenticator designed by D. J. Bernstein.
// Poly1305 takes a 32-byte one-time key and a message and produces a
// 16-byte tag.  This tag is used to authenticate the message.
void
poly1305_mac(bytes key, bytes text, bytes& tag)
{
  // This works everywhere. Let's use it as a base for comparisons.
  bytes tag_32 = std::vector<uint8_t>(POLY1305_TAG_SIZE);
  std::cout << "Poly1305.Mac (32)" << std::endl;
  Hacl_Poly1305_32_poly1305_mac(
    tag_32.data(), text.size(), text.data(), key.data());

#ifdef HACL_CAN_COMPILE_VEC128
  if (hacl_vec128_support()) {
    bytes tag_128 = std::vector<uint8_t>(POLY1305_TAG_SIZE);
    std::cout << "Poly1305.Mac (VEC128)" << std::endl;
    Hacl_Poly1305_128_poly1305_mac(
      tag_128.data(), text.size(), text.data(), key.data());

    EXPECT_EQ(tag_32, tag_128)
      << "Detected difference between _32 and _128 version";
  } else {
    std::cout << "No support for VEC128 on this CPU." << std::endl;
  }
#endif

#ifdef HACL_CAN_COMPILE_VEC256
  if (hacl_vec256_support()) {
    bytes tag_256 = std::vector<uint8_t>(POLY1305_TAG_SIZE);
    std::cout << "Poly1305.Mac (VEC256)" << std::endl;
    Hacl_Poly1305_256_poly1305_mac(
      tag_256.data(), text.size(), text.data(), key.data());

    EXPECT_EQ(tag_32, tag_256)
      << "Detected difference between _32 and _256 version";
  } else {
    std::cout << "No support for VEC256 on this CPU." << std::endl;
  }
#endif

  tag = tag_32;
}

void
poly1305_mac_streaming(bytes key, bytes text, bytes& tag)
{
  auto random_text = split_vector_randomly(text);

  bytes tag_32 = std::vector<uint8_t>(POLY1305_TAG_SIZE);

  std::cout << "Poly1305.Mac (32, Streaming)" << std::endl;
  std::vector<uint64_t> ctx(32);
  Hacl_Poly1305_32_poly1305_init(ctx.data(), key.data());
  for (auto chunk : random_text) {
    Hacl_Poly1305_32_poly1305_update(ctx.data(), chunk.size(), chunk.data());
  }
  Hacl_Poly1305_32_poly1305_finish(tag_32.data(), key.data(), ctx.data());

#ifdef HACL_CAN_COMPILE_VEC128
  if (hacl_vec128_support()) {
    bytes tag_128 = std::vector<uint8_t>(POLY1305_TAG_SIZE);

    std::cout << "Poly1305.Mac (VEC128, Streaming)" << std::endl;
    Hacl_Poly1305_128_poly1305_ctx ctx = 0;
    Hacl_Poly1305_128_poly1305_init(ctx, key.data());
    for (auto chunk : random_text) {
      Hacl_Poly1305_128_poly1305_update(ctx, chunk.size(), chunk.data());
    }
    Hacl_Poly1305_128_poly1305_finish(tag_128.data(), key.data(), ctx);

    EXPECT_EQ(tag_32, tag_128)
      << "Detected difference between _32 and _128 version";
  } else {
    std::cout << "No support for VEC128 on this CPU." << std::endl;
  }
#endif

#ifdef HACL_CAN_COMPILE_VEC256
  if (hacl_vec256_support()) {
    bytes tag_256 = std::vector<uint8_t>(POLY1305_TAG_SIZE);

    std::cout << "Poly1305.Mac (VEC256, Streaming)" << std::endl;
    Hacl_Poly1305_256_poly1305_ctx ctx = 0;
    Hacl_Poly1305_256_poly1305_init(ctx, key.data());
    for (auto chunk : random_text) {
      Hacl_Poly1305_256_poly1305_update(ctx, chunk.size(), chunk.data());
    }
    Hacl_Poly1305_256_poly1305_finish(tag_256.data(), key.data(), ctx);

    EXPECT_EQ(tag_32, tag_256)
      << "Detected difference between _32 and _128 version";
  } else {
    std::cout << "No support for VEC256 on this CPU." << std::endl;
  }
#endif

  tag = tag_32;
}

class Poly1305Suite : public ::testing::TestWithParam<TestCase>
{};

TEST_P(Poly1305Suite, TestCase)
{
  TestCase test = GetParam();

  std::cout << "Running " << test.comment << "..." << std::endl;

  // Test API
  {
    bytes got = std::vector<uint8_t>(POLY1305_TAG_SIZE);
    poly1305_mac(test.key, test.tag, got);

    EXPECT_EQ(test.tag, got);
  }

  // Test Streaming API
  {
    bytes got = std::vector<uint8_t>(POLY1305_TAG_SIZE);
    poly1305_mac_streaming(test.key, test.tag, got);

    EXPECT_EQ(test.tag, got);
  }
}

std::vector<TestCase>
read_json(char* path)
{
  json raw_tests;
  std::ifstream file(path);
  file >> raw_tests;

  std::vector<TestCase> tests;

  for (auto& test_raw : raw_tests.items()) {
    auto test = test_raw.value();

    //    auto m = std::vector<bytes>(test["m"].size());
    //    for (auto& m_raw : test["m"].items()) {
    //      m.push_back(from_hex(m_raw.value()));
    //    }
    //
    //    auto c = std::vector<bytes>(test["c"].size());
    //    for (auto& c_raw : test["c"].items()) {
    //      c.push_back(from_hex(c_raw.value()));
    //    }
    //

    std::string comment = test["comment"];
    bytes key = from_hex(test["key"]);
    bytes text = from_hex(test["text"]);
    bytes tag = from_hex(test["tag"]);

    //    bytes r = from_hex(test["r"]);
    //    bytes mr = from_hex(test["mr"]);
    //    bytes k = from_hex(test["k"]);
    //    bytes n = from_hex(test["n"]);
    //    bytes AESkn = from_hex(test["AESkn"]);
    //    bytes mac = from_hex(test["mac"]);

    tests.push_back(TestCase{
      .comment = comment, .key = key, .text = text, .tag = tag,
      //      .m = m,
      //      .c = c,
      //      .r = r,
      //      .mr = mr,
      //      .k = k,
      //      .n = n,
      //      .AESkn = AESkn,
      //      .mac = mac,
    });

    // FIXME: Test others, too.
    if (tests.size() >= 2) {
      break;
    }
  }

  return tests;
}

INSTANTIATE_TEST_SUITE_P(
  Poly1305RFC8439,
  Poly1305Suite,
  ::testing::ValuesIn(read_json(const_cast<char*>("poly1305_rfc8439.json"))));
