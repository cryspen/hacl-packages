/* Hand-written file */

#pragma once

#ifdef HACL_CAN_COMPILE_VEC256
#include "libintvector.h"
typedef struct libcrux_digest_Shake128StateX4
{
  Lib_IntVector_Intrinsics_vec256* x4;
} libcrux_digest_Shake128StateX4;
typedef libcrux_digest_Shake128StateX4 libcrux_digest_Shake128StateX2;
typedef libcrux_digest_Shake128StateX4 libcrux_digest_Shake128StateX3;
#else
typedef struct libcrux_digest_Shake128State
{
  uint64_t* st;
} libcrux_digest_Shake128State;
#endif
