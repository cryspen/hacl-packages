/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <gtest/gtest.h>

#include "hacl-cpu-features.h"

#include "Hacl_Hash_Blake2.h"
#include "blake2_vectors.h"
#include "config.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_256.h"
#endif

#define VALE                                                                   \
  TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64 ||                         \
    TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X86

#if VALE
// Only include this for checking CPU flags.
#include "Vale.h"
#endif

// Function pointer to multiplex between the different implementations.
typedef void (
  *test_blake)(uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*);

bool
test_blake2b(test_blake blake,
             size_t input_len,
             uint8_t* input,
             size_t key_len,
             uint8_t* key,
             size_t expected_len,
             uint8_t* expected)
{
  bytes comp(expected_len, 0);
  (*blake)(expected_len, comp.data(), input_len, input, key_len, key);
  return compare_and_print(expected_len, comp.data(), expected);
}

class Blake2bTesting : public ::testing::TestWithParam<blake2_test_vector>
{};

TEST_P(Blake2bTesting, TryTestVectors)
{
  const blake2_test_vector& vectors2b(GetParam());
  bool test = test_blake2b(&Hacl_Blake2b_32_blake2b,
                           vectors2b.input_len,
                           vectors2b.input,
                           vectors2b.key_len,
                           vectors2b.key,
                           vectors2b.expected_len,
                           vectors2b.expected);
  EXPECT_TRUE(test);

#ifdef HACL_CAN_COMPILE_VEC256
  // We might have compiled vec256 blake2b but don't have it available on the
  // CPU when running now.
  if (hacl_vec256_support()) {
    test = test_blake2b(&Hacl_Blake2b_256_blake2b,
                        vectors2b.input_len,
                        vectors2b.input,
                        vectors2b.key_len,
                        vectors2b.key,
                        vectors2b.expected_len,
                        vectors2b.expected);
    EXPECT_TRUE(test);
  } else {
    printf(" ! Vec256 was compiled but AVX2 is not available on this CPU.\n");
  }
#endif
}

INSTANTIATE_TEST_SUITE_P(TestVectors,
                         Blake2bTesting,
                         ::testing::ValuesIn(vectors2b));
