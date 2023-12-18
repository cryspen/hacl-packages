#pragma once

#include "eurydice_glue.h"

typedef struct
  __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__s
{
  uint8_t fst[840U];
  uint8_t snd[840U];
  uint8_t thd[840U];
  uint8_t f3[840U];
} __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_;

extern void
libcrux_digest_shake256(size_t len, Eurydice_slice input, uint8_t* out);

extern void
libcrux_digest_shake128(size_t len, Eurydice_slice input, uint8_t* out);

extern __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
libcrux_digest_shake128x4(size_t len,
                          Eurydice_slice input0,
                          Eurydice_slice input1,
                          Eurydice_slice input2,
                          Eurydice_slice input3);
