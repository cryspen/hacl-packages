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

inline libcrux_digest_Shake128StateX2 libcrux_digest_shake128_init_x2(void){
  #ifdef HACL_CAN_COMPILE_VEC256
  return (libcrux_digest_Shake128StateX2) {.x4 = Hacl_Hash_SHA3_Simd256_state_malloc()}
  #else
  uint64_t* st0 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st1 = Hacl_Hash_SHA3_Scalar_state_malloc();
  return (libcrux_digest_Shake128StateX2) { .st0 = st0, .st1 = st1 };
  #endif
}

inline libcrux_digest_Shake128StateX3 libcrux_digest_shake128_init_x3(void){
  #ifdef HACL_CAN_COMPILE_VEC256
  return (libcrux_digest_Shake128StateX3) {.x4 = Hacl_Hash_SHA3_Simd256_state_malloc()}
  #else
  uint64_t* st0 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st1 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st2 = Hacl_Hash_SHA3_Scalar_state_malloc();
  return (libcrux_digest_Shake128StateX3) { .st0 = st0, .st1 = st1, .st2 = st2 };
  #endif
}

inline libcrux_digest_Shake128StateX4 libcrux_digest_shake128_init_x4(void){
  #ifdef HACL_CAN_COMPILE_VEC256
  return (libcrux_digest_Shake128StateX4) {.x4 = Hacl_Hash_SHA3_Simd256_state_malloc()}
  #else
  uint64_t* st0 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st1 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st2 = Hacl_Hash_SHA3_Scalar_state_malloc();
  uint64_t* st3 = Hacl_Hash_SHA3_Scalar_state_malloc();
  return (libcrux_digest_Shake128StateX4) { .st0 = st0, .st1 = st1, .st2 = st2, .st3 = st3 };
  #endif
}

inline void
libcrux_digest_shake128_absorb_final_x2(
  libcrux_digest_Shake128StateX2 *x0,
  Eurydice_slice x1,
  Eurydice_slice x2
) {
  assert (x1.len == x2.len);
  #ifdef HACL_CAN_COMPILE_VEC256
  return Hacl_Hash_SHA3_Simd256_shake128_absorb_final(
    x0->x4,
    x1.ptr,
    x2.ptr,
    x1.ptr,
    x2.ptr,
    x1.len
  );
  #else
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st0,x1.ptr,x1.len);
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st1,x2.ptr,x2.len);
  #endif
}

inline void
libcrux_digest_shake128_absorb_final_x3(
  libcrux_digest_Shake128StateX3 *x0,
  Eurydice_slice x1,
  Eurydice_slice x2,
  Eurydice_slice x3
) {
  assert (x1.len == x2.len && x1.len == x3.len);
  #ifdef HACL_CAN_COMPILE_VEC256
  return Hacl_Hash_SHA3_Simd256_shake128_absorb_final(
    x0->x4,
    x1.ptr,
    x2.ptr,
    x3.ptr,
    x1.ptr,
    x1.len
  );
  #else
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st0,x1.ptr,x1.len);
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st1,x2.ptr,x2.len);
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st2,x3.ptr,x3.len);
  #endif
}

inline void
libcrux_digest_shake128_absorb_final_x4(
  libcrux_digest_Shake128StateX4 *x0,
  Eurydice_slice x1,
  Eurydice_slice x2,
  Eurydice_slice x3,
  Eurydice_slice x4
) {
  assert (x1.len == x2.len && x1.len == x3.len && x1.len == x4.len);
  #ifdef HACL_CAN_COMPILE_VEC256
  return Hacl_Hash_SHA3_Simd256_shake128_absorb_final(
    x0->x4,
    x1.ptr,
    x2.ptr,
    x3.ptr,
    x4.ptr,
    x1.len
  );
  #else
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st0,x1.ptr,x1.len);
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st1,x2.ptr,x2.len);
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st2,x3.ptr,x3.len);
  Hacl_Hash_SHA3_Scalar_shake128_absorb_final(x0->st3,x4.ptr,x4.len);
  #endif
}

inline void
libcrux_digest_shake128_squeeze_nblocks_x2(
  size_t output_bytes,
  libcrux_digest_Shake128StateX2 *x0,
  uint8_t* output[2]
) {
  #ifdef HACL_CAN_COMPILE_VEC256
  uint8_t* tmp0 = KRML_ALIGNED_MALLOC(output_bytes);
  uint8_t* tmp1 = KRML_ALIGNED_MALLOC(output_bytes);
  return Hacl_Hash_SHA3_Simd256_shake128_squeeze_nblocks(
    x0->x4,
    output[0],
    output[1],
    tmp0,
    tmp1,
    output_bytes
  );
  #else
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[0],output_bytes);
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[1],output_bytes);
  #endif
}

inline void
libcrux_digest_shake128_squeeze_nblocks_x3(
  size_t output_bytes,
  libcrux_digest_Shake128StateX2 *x0,
  uint8_t* output[3]
) {
  #ifdef HACL_CAN_COMPILE_VEC256
  uint8_t* tmp0 = KRML_ALIGNED_MALLOC(output_bytes);
  return Hacl_Hash_SHA3_Simd256_shake128_squeeze_nblocks(
    x0->x4,
    output[0],
    output[1],
    output[2],
    tmp0,
    output_bytes
  );
  #else
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[0],output_bytes);
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[1],output_bytes);
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[2],output_bytes);
  #endif
}

inline void
libcrux_digest_shake128_squeeze_nblocks_x4(
  size_t output_bytes,
  libcrux_digest_Shake128StateX2 *x0,
  uint8_t* output[4]
) {
  #ifdef HACL_CAN_COMPILE_VEC256
  return Hacl_Hash_SHA3_Simd256_shake128_squeeze_nblocks(
    x0->x4,
    output[0],
    output[1],
    output[2],
    output[3],
    output_bytes
  );
  #else
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[0],output_bytes);
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[1],output_bytes);
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[2],output_bytes);
  Hacl_Hash_SHA3_Scalar_shake128_squeeze_nblocks(x0->st0,output[3],output_bytes);
  #endif
}

