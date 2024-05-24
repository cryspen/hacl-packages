#include "libcrux_hacl_glue.h"
#include "Hacl_Hash_SHA3.h"
#include "libcrux_digest.h"
#include "libcrux_platform.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "EverCrypt_AutoConfig2.h"
#include "Hacl_Hash_SHA3_Simd256.h"
#endif
#include "Hacl_Hash_SHA3_Scalar.h"

static int evercrypt_initialized = false;

bool
libcrux_platform_simd256_support(void)
{
#ifdef HACL_CAN_COMPILE_VEC256
  // TODO: call runtime CPU detection to detect whether the target machine does
  // have AVX2
  if (!evercrypt_initialized) {
    EverCrypt_AutoConfig2_init();
    evercrypt_initialized = true;
  }
  return EverCrypt_AutoConfig2_has_avx2();
#endif
  return false;
}

inline void
libcrux_sha3_portable_shake256_(size_t len, uint8_t* out, Eurydice_slice input)
{
  Hacl_Hash_SHA3_shake256_hacl(input.len, input.ptr, (uint32_t)len, out);
}

inline void
libcrux_digest_shake128_(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_Hash_SHA3_shake128_hacl(input.len, input.ptr, (uint32_t)len, out);
}

inline void
libcrux_sha3_portable_sha512(Eurydice_slice x0, Eurydice_slice x1)
{
  Hacl_Hash_SHA3_sha3_512(x1.ptr, x0.ptr, (uint32_t)x0.len);
}

inline void
libcrux_sha3_portable_sha256(Eurydice_slice x0, Eurydice_slice x1)
{
  Hacl_Hash_SHA3_sha3_256(x1.ptr, x0.ptr, (uint32_t)x0.len);
}



inline libcrux_sha3_portable_KeccakState1
libcrux_sha3_portable_incremental_shake128_init(void)
{
  libcrux_sha3_portable_KeccakState1 st;
  st.st = Hacl_Hash_SHA3_Scalar_state_malloc();
  return st;
}

inline void
libcrux_sha3_portable_incremental_shake128_absorb_final(
  libcrux_sha3_portable_KeccakState1* state,
  Eurydice_slice x1)
{
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(
    state->st, x1.ptr, (uint32_t)x1.len);
}

inline void
libcrux_sha3_portable_incremental_shake128_squeeze_first_three_blocks(
  libcrux_sha3_portable_KeccakState1* x0,
  Eurydice_slice x1)
{
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st, x1.ptr, x1.len);
}

inline void
libcrux_sha3_portable_incremental_shake128_squeeze_next_block(
  libcrux_sha3_portable_KeccakState1* x0,
  Eurydice_slice x1)
{
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st, x1.ptr, x1.len);
}

