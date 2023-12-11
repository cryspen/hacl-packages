#pragma once

#include "Hacl_Hash_SHA3_Scalar.h"

#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Hash_SHA3_Simd256.h"
#endif

#include "libcrux_kyber.h"

bool libcrux_platform_simd256_support(void) {
    // TODO: Replace this with HACL platform support.
    return false;
}

static inline size_t
libcrux_digest_digest_size(libcrux_digest_Algorithm x0)
{
  if (x0 == libcrux_digest_Sha3_512) {
    return 64;
  } else if (x0 == libcrux_digest_Sha3_256) {
    return 32;
  } else {
    return KRML_HOST_EXIT;
  }
}

static inline void
libcrux_digest_shake256(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_Hash_SHA3_Scalar_shake256(input.len, input.ptr, (uint32_t)len, out);
}

static inline void
libcrux_digest_shake128(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_Hash_SHA3_Scalar_shake128(input.len, input.ptr, (uint32_t)len, out);
}

static inline __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
libcrux_digest_shake128x4(size_t len,
                          Eurydice_slice input0,
                          Eurydice_slice input1,
                          Eurydice_slice input2,
                          Eurydice_slice input3)
{
#ifdef HACL_CAN_COMPILE_VEC256
  Hacl_Hash_SHA3_Simd256_shake128(input0.len,
                                  input0.ptr,
                                  input1.ptr,
                                  input2.ptr,
                                  input3.ptr,
                                  (uint32_t)len,
                                  out);
#else
  __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
    out =
      (__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_)
  {
    .fst = { 0 }, .snd = { 0 }, .thd = { 0 }, .f3 = { 0 }
  };
  Hacl_Hash_SHA3_Scalar_shake128(
    input0.len, input0.ptr, (uint32_t)len, out.fst);
  Hacl_Hash_SHA3_Scalar_shake128(
    input1.len, input1.ptr, (uint32_t)len, out.snd);
  Hacl_Hash_SHA3_Scalar_shake128(
    input2.len, input2.ptr, (uint32_t)len, out.thd);
  Hacl_Hash_SHA3_Scalar_shake128(input3.len, input3.ptr, (uint32_t)len, out.f3);
  return out;
#endif
}

static inline void
libcrux_digest_sha3_512(Eurydice_slice x0, uint8_t x1[64U])
{
  Hacl_Hash_SHA3_Scalar_sha3_512((uint32_t)x0.len, x0.ptr, x1);
}

static inline void
libcrux_digest_sha3_256(Eurydice_slice x0, uint8_t x1[64U])
{
  Hacl_Hash_SHA3_Scalar_sha3_256((uint32_t)x0.len, x0.ptr, x1);
}
