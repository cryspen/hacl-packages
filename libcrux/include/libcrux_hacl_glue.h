/* Hand-written file */

#pragma once

#if defined(__cplusplus)
extern "C"
{
#endif

#include "Eurydice.h"

#include <stdint.h>
#include <string.h>
#include "libcrux_digest.h"

typedef struct KeccakState1{
  uint64_t* st;
} libcrux_sha3_portable_KeccakState1;

libcrux_sha3_portable_KeccakState1
libcrux_sha3_portable_incremental_shake128_init(void);

void
libcrux_sha3_portable_incremental_shake128_absorb_final(
  libcrux_sha3_portable_KeccakState1* state,
  Eurydice_slice x1);

void
libcrux_sha3_portable_incremental_shake128_squeeze_next_block(
  libcrux_sha3_portable_KeccakState1* x0,
  Eurydice_slice x1);

void
libcrux_sha3_portable_incremental_shake128_squeeze_first_three_blocks(
  libcrux_sha3_portable_KeccakState1* x0,
  Eurydice_slice x1);

#if defined(__cplusplus)
}
#endif
