#include "libcrux_hacl_glue.h"
#include "Hacl_Hash_SHA3.h"
#include "libcrux_kyber.h"

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
libcrux_digest_shake256f(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_Hash_SHA3_shake256_hacl(input.len, input.ptr, (uint32_t)len, out);
}

inline void
libcrux_digest_shake128f(size_t len, Eurydice_slice input, uint8_t* out)
{
  Hacl_Hash_SHA3_shake128_hacl(input.len, input.ptr, (uint32_t)len, out);
}

inline __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
libcrux_digest_shake128x4f(size_t len,
                           Eurydice_slice input0,
                           Eurydice_slice input1,
                           Eurydice_slice input2,
                           Eurydice_slice input3)
{
  __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
    out =
      (__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_){
        .fst = { 0 }, .snd = { 0 }, .thd = { 0 }, .f3 = { 0 }
      };
#ifdef HACL_CAN_COMPILE_VEC256
  if (libcrux_platform_simd256_support() == true) {
    Hacl_Hash_SHA3_Simd256_shake128(input0.len,
                                    input0.ptr,
                                    input1.ptr,
                                    input2.ptr,
                                    input3.ptr,
                                    (uint32_t)len,
                                    out.fst,
                                    out.snd,
                                    out.thd,
                                    out.f3);
  } else {
    Hacl_Hash_SHA3_shake128_hacl(
      input0.len, input0.ptr, (uint32_t)len, out.fst);
    Hacl_Hash_SHA3_shake128_hacl(
      input1.len, input1.ptr, (uint32_t)len, out.snd);
    Hacl_Hash_SHA3_shake128_hacl(
      input2.len, input2.ptr, (uint32_t)len, out.thd);
    Hacl_Hash_SHA3_shake128_hacl(input3.len, input3.ptr, (uint32_t)len, out.f3);
  }
#else
  Hacl_Hash_SHA3_shake128_hacl(input0.len, input0.ptr, (uint32_t)len, out.fst);
  Hacl_Hash_SHA3_shake128_hacl(input1.len, input1.ptr, (uint32_t)len, out.snd);
  Hacl_Hash_SHA3_shake128_hacl(input2.len, input2.ptr, (uint32_t)len, out.thd);
  Hacl_Hash_SHA3_shake128_hacl(input3.len, input3.ptr, (uint32_t)len, out.f3);
#endif
  return out;
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
