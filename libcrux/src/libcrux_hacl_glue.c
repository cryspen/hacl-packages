#include "libcrux_kyber.h"
#include "libcrux_hacl_glue.h"
#include "Hacl_Hash_SHA3.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_SHA3_Simd256.h"
#else
#include "Hacl_Hash_SHA3_Scalar.h"
#endif

bool
libcrux_platform_simd256_support(void)
{
  // TODO: Replace this with HACL platform support.
  return false;
}

inline void
libcrux_digest_shake256_(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_Hash_SHA3_shake256_hacl(input.len, input.ptr, (uint32_t)len, out);
}

inline void
libcrux_digest_shake128_(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_Hash_SHA3_shake128_hacl(input.len, input.ptr, (uint32_t)len, out);
}

inline void
libcrux_digest_sha3_512(Eurydice_slice x0, uint8_t x1[64U])
{
  Hacl_Hash_SHA3_sha3_512(x1, x0.ptr, (uint32_t)x0.len);
}

inline void
libcrux_digest_sha3_256(Eurydice_slice x0, uint8_t x1[32U])
{
  Hacl_Hash_SHA3_sha3_256(x1, x0.ptr, (uint32_t)x0.len);
}

inline libcrux_digest_Shake128State libcrux_digest_shake128_init(void) {
  #ifdef HACL_CAN_COMPILE_VEC256
  return (libcrux_digest_Shake128State) {.x4 = (Lib_IntVector_Intrinsics_vec256*) Hacl_Hash_SHA3_Simd256_state_malloc()};
  #else
  uint64_t* st = Hacl_Hash_SHA3_Scalar_state_malloc();
  return (libcrux_digest_Shake128State) { .st = st };
  #endif
}

void
libcrux_digest_shake128_absorb_final(libcrux_digest_Shake128State *x0, Eurydice_slice x1) {
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st,x1.ptr,x1.len);
}

inline void
libcrux_digest_shake128_squeeze_nblocks_(
  size_t x0,
  libcrux_digest_Shake128State *x1,
  uint8_t *x2
) {
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x1->st,x2,x0);
}
