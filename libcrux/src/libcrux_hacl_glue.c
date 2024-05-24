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
libcrux_sha3_portable_sha512(Eurydice_slice x0, uint8_t x1[64U])
{
  Hacl_Hash_SHA3_sha3_512(x1, x0.ptr, (uint32_t)x0.len);
}

inline void
libcrux_sha3_portable_sha256(Eurydice_slice x0, uint8_t x1[32U])
{
  Hacl_Hash_SHA3_sha3_256(x1, x0.ptr, (uint32_t)x0.len);
}

inline libcrux_sha3_portable_KeccakState1
libcrux_sha3_portable_incremental_shake128_init(void)
{
#ifdef HACL_CAN_COMPILE_VEC256
  if (libcrux_platform_simd256_support()) {
    return (libcrux_sha3_portable_KeccakState1){
      .x4 = Hacl_Hash_SHA3_Simd256_state_malloc(),
      .st0 = NULL,
      .st1 = NULL,
      .st2 = NULL,
      .st3 = NULL,
    };
  } else {
    uint64_t* st0 = Hacl_Hash_SHA3_Scalar_state_malloc();
    uint64_t* st1 = Hacl_Hash_SHA3_Scalar_state_malloc();
    uint64_t* st2 = Hacl_Hash_SHA3_Scalar_state_malloc();
    uint64_t* st3 = Hacl_Hash_SHA3_Scalar_state_malloc();
    return (libcrux_sha3_portable_KeccakState1){
      .x4 = NULL, .st0 = st0, .st1 = st1, .st2 = st2, .st3 = st3
    };
  }
#else
  uint64_t* st0 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st1 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st2 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st3 = Hacl_Hash_SHA3_Scalar_state_malloc();
  return (libcrux_sha3_portable_KeccakState1){
    .st0 = st0, .st1 = st1, .st2 = st2, .st3 = st3
  };
#endif
}

// inline void
// libcrux_digest_incremental_x4__libcrux__digest__incremental_x4__Shake128StateX4__absorb_final_(
//   size_t k,
//   libcrux_digest_incremental_x4_Shake128StateX4* state,
//   // Eurydice_slice x1[k])
//   Eurydice_slice* x1)
// {
void
libcrux_sha3_portable_incremental_shake128_absorb_final(
  libcrux_sha3_portable_KeccakState1* state,
  Eurydice_slice x1)
{
#ifdef HACL_CAN_COMPILE_VEC256
  if (libcrux_platform_simd256_support()) {
#TODO
  } else {
// This function requires that the data be no longer than a partial block,
// meaning we can safely downcast into a uint32_t.
#TODO
  }
#else
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(
    state->st0, x1.ptr, (uint32_t)x1.len);
#endif
}

inline void
libcrux_sha3_portable_incremental_shake128_squeeze_first_three_blocks(
  libcrux_sha3_portable_KeccakState1* x0,
  Eurydice_slice x1)
{
#ifdef HACL_CAN_COMPILE_VEC256
  if (libcrux_platform_simd256_support()) {
// FIXME: the API does not allow aliased inputs -- discuss with Mamone
#TODO
  } else {
#TODO
#else
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0, x1.ptr, x1.len);
#endif
  }

  inline void
  libcrux_digest_incremental_x4__libcrux__digest__incremental_x4__Shake128StateX4__free_memory(
    libcrux_digest_incremental_x4_Shake128StateX4 x0)
  {
#ifdef HACL_CAN_COMPILE_VEC256
    if (libcrux_platform_simd256_support()) {
      Hacl_Hash_SHA3_Simd256_state_free(x0.x4);
    } else {
      Hacl_Hash_SHA3_Scalar_state_free(x0.st0);
      Hacl_Hash_SHA3_Scalar_state_free(x0.st1);
      Hacl_Hash_SHA3_Scalar_state_free(x0.st2);
      Hacl_Hash_SHA3_Scalar_state_free(x0.st3);
    }
#else
  Hacl_Hash_SHA3_Scalar_state_free(x0.st0);
  Hacl_Hash_SHA3_Scalar_state_free(x0.st1);
  Hacl_Hash_SHA3_Scalar_state_free(x0.st2);
  Hacl_Hash_SHA3_Scalar_state_free(x0.st3);
#endif
  }
