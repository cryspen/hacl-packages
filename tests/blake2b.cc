#include <gtest/gtest.h>

#include "Hacl_Hash_Blake2.h"
#include "blake2_vectors.h"
#include "config.h"
#include "util.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_Blake2b_256.h"
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

  uint8_t comp[expected_len];
  memset(comp, 0, expected_len * sizeof comp[0]);
  (*blake)(expected_len, comp, input_len, input, key_len, key);
  return compare_and_print(expected_len, comp, expected);
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
  test = test_blake2b(&Hacl_Blake2b_256_blake2b,
                      vectors2b.input_len,
                      vectors2b.input,
                      vectors2b.key_len,
                      vectors2b.key,
                      vectors2b.expected_len,
                      vectors2b.expected);
  EXPECT_TRUE(test);
#endif
}

INSTANTIATE_TEST_SUITE_P(TestVectors,
                         Blake2bTesting,
                         ::testing::ValuesIn(vectors2b));
