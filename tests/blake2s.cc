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

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#endif

#include "blake2_vectors.h"
#include "util.h"

bool
print_test2s(int in_len,
             uint8_t* in,
             int key_len,
             uint8_t* key,
             int exp_len,
             uint8_t* exp)
{
  bytes comp(exp_len, 0);

#ifdef HACL_CAN_COMPILE_VEC128
  Hacl_Blake2s_128_blake2s(exp_len, comp.data(), in_len, in, key_len, key);
  printf("testing blake2s vec-128:\n");
  bool ok = compare_and_print(exp_len, comp.data(), exp);
#else
  printf(" !!! NO TESTS RUN! NO VEC128 SUPPORT! !!!\n");
  bool ok = true;
#endif

  return ok;
}

class Blake2sTesting : public ::testing::TestWithParam<blake2_test_vector>
{};

TEST_P(Blake2sTesting, TryTestVectors)
{
  const blake2_test_vector& vectors2s(GetParam());
  bool test = print_test2s(vectors2s.input_len,
                           vectors2s.input,
                           vectors2s.key_len,
                           vectors2s.key,
                           vectors2s.expected_len,
                           vectors2s.expected);
  EXPECT_TRUE(test);
}

INSTANTIATE_TEST_SUITE_P(TestVectors,
                         Blake2sTesting,
                         ::testing::ValuesIn(vectors2s));
