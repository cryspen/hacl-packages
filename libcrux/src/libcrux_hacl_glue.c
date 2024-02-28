#include "libcrux_kyber.h"
#include "libcrux_hacl_glue.h"
#include "Hacl_Hash_SHA3.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_SHA3_Simd256.h"
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

extern libcrux_digest_Shake128StateX2 libcrux_digest_shake128_init_x2(void);

extern libcrux_digest_Shake128StateX3 libcrux_digest_shake128_init_x3(void);

extern libcrux_digest_Shake128StateX4 libcrux_digest_shake128_init_x4(void);

extern void
libcrux_digest_shake128_absorb_final_x2(
  libcrux_digest_Shake128StateX2 *x0,
  Eurydice_slice x1,
  Eurydice_slice x2
);

extern void
libcrux_digest_shake128_absorb_final_x3(
  libcrux_digest_Shake128StateX3 *x0,
  Eurydice_slice x1,
  Eurydice_slice x2,
  Eurydice_slice x3
);

extern void
libcrux_digest_shake128_absorb_final_x4(
  libcrux_digest_Shake128StateX4 *x0,
  Eurydice_slice x1,
  Eurydice_slice x2,
  Eurydice_slice x3,
  Eurydice_slice x4
);
