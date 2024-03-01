/* Hand-written file */

#pragma once

#ifdef HACL_CAN_COMPILE_VEC256
#include "libintvector.h"
typedef struct libcrux_digest_Shake128StateX4 {
    Lib_IntVector_Intrinsics_vec256* x4;
} libcrux_digest_Shake128StateX4;
typedef libcrux_digest_Shake128StateX4 libcrux_digest_Shake128StateX2;
typedef libcrux_digest_Shake128StateX4 libcrux_digest_Shake128StateX3;
#else
typedef struct libcrux_digest_Shake128StateX2 {
  uint64_t* st0;
  uint64_t* st1;
} libcrux_digest_Shake128StateX2;
typedef struct libcrux_digest_Shake128StateX3 {
  uint64_t* st0;
  uint64_t* st1;
  uint64_t* st2;
} libcrux_digest_Shake128StateX3;
typedef struct libcrux_digest_Shake128StateX4 {
  uint64_t* st0;
  uint64_t* st1;
  uint64_t* st2;
  uint64_t* st3;
} libcrux_digest_Shake128StateX4;
#endif

extern void
libcrux_digest_shake128_squeeze_nblocks_x2_(
  size_t output_bytes,
  libcrux_digest_Shake128StateX2 *x0,
  uint8_t* output
);

#define libcrux_digest_shake128_squeeze_nblocks_x2(a,b,c,d) libcrux_digest_shake128_squeeze_nblocks_x2_(a,b,c)

extern void
libcrux_digest_shake128_squeeze_nblocks_x3_(
  size_t output_bytes,
  libcrux_digest_Shake128StateX3 *x0,
  uint8_t* output
);

#define libcrux_digest_shake128_squeeze_nblocks_x3(a,b,c,d) libcrux_digest_shake128_squeeze_nblocks_x3_(a,b,c)

extern void
libcrux_digest_shake128_squeeze_nblocks_x4_(
  size_t output_bytes,
  libcrux_digest_Shake128StateX4 *x0,
  uint8_t* output  
);

#define libcrux_digest_shake128_squeeze_nblocks_x4(a,b,c,d) libcrux_digest_shake128_squeeze_nblocks_x4_(a,b,c)