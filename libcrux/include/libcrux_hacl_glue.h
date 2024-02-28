/* Hand-written file */

#pragma once

#ifdef HACL_CAN_COMPILE_VEC256
typedef struct libcrux_digest_Shake128StateX4 {
    Lib_IntVector_Intrinsics_vec256* x4
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
