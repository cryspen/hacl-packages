#include <gtest/gtest.h>

#include "Hacl_Curve25519_51.h"
#include "curve25519_vectors.h"

#define VALE TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64

#if VALE
#include "Hacl_Curve25519_64.h"
#endif

#include "config.h"
#include "util.h"

TEST(x25519Test, HaclTest)
{
  for (int i = 0; i < sizeof(vectors) / sizeof(curve25519_test_vector); ++i) {
    uint8_t comp[32] = { 0 };
    Hacl_Curve25519_51_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
    EXPECT_TRUE(print_result(32, comp, vectors[i].secret));

#if VALE
    memset(comp, 0, 32);
    Hacl_Curve25519_64_ecdh(comp, vectors[i].scalar, vectors[i].public_key);
    EXPECT_TRUE(print_result(32, comp, vectors[i].secret));
#endif
  }
}
