#include <gtest/gtest.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>

#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Hash_Blake2s_128.h"
#endif

#include "util.h"

#include "EverCrypt_AutoConfig2.h"
#include "blake2_vectors.h"

bool print_test2s(int in_len, uint8_t *in, int key_len, uint8_t *key, int exp_len, uint8_t *exp)
{
    uint8_t comp[exp_len];
    memset(comp, 0, exp_len * sizeof comp[0]);

#ifdef HACL_CAN_COMPILE_VEC128
    Hacl_Blake2s_128_blake2s(exp_len, comp, in_len, in, key_len, key);
    printf("testing blake2s vec-128:\n");
    bool ok = print_result(exp_len, comp, exp);
#else
    printf(" !!! NO TESTS RUN! NO VEC128 SUPPORT! !!!\n");
    bool ok = true;
#endif

    return ok;
}

// FIXME: Make this a TEST_P
TEST(Blake2sTest, BasicKAT)
{
    for (int i = 0; i < sizeof(vectors2s) / sizeof(blake2_test_vector); ++i)
    {
        EXPECT_TRUE(print_test2s(vectors2s[i].input_len, vectors2s[i].input, vectors2s[i].key_len, vectors2s[i].key, vectors2s[i].expected_len, vectors2s[i].expected));
    }
}
